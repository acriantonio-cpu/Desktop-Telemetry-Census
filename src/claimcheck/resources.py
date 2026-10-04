"""Hardware/resource awareness: doctor checks, guards used during capture, worker sizing.

Nothing here changes system settings; it only measures and advises (or aborts a capture safely).
"""

from __future__ import annotations

import ctypes
import os
import platform
import shlex
import shutil
import subprocess  # argv lists only, never shell=True; commands come from the user's own manifest  # nosec B404
import sys
from dataclasses import dataclass
from pathlib import Path

import psutil

MB = 1024 * 1024


@dataclass
class Check:
    name: str
    status: str  # OK | WARN | FAIL | INFO
    detail: str
    advice: str = ""


def is_admin() -> bool:
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def free_disk_mb(path: Path) -> float:
    p = Path(path)
    while not p.exists() and p != p.parent:
        p = p.parent
    return shutil.disk_usage(p).free / MB


def avail_ram_mb() -> float:
    return psutil.virtual_memory().available / MB


def total_ram_mb() -> float:
    return psutil.virtual_memory().total / MB


def cpu_count() -> int:
    return os.cpu_count() or 1


def recommend_static_workers(chunk_mb: int = 8) -> int:
    """Conservative: leave 1 core for the OS, cap by RAM (each worker holds ~3 chunks), max 4."""
    by_cpu = max(1, cpu_count() - 1)
    by_ram = max(1, int(avail_ram_mb() // max(1, chunk_mb * 3 + 200)))
    return max(1, min(4, by_cpu, by_ram))


def split_command(cmd: str) -> list[str]:
    """Split a command string ('mitmdump' or 'python -m mitmproxy.tools.dump') into argv, Windows-safe."""
    if not cmd:
        return []
    parts = shlex.split(cmd, posix=(os.name != "nt"))
    if os.name == "nt":  # non-POSIX shlex keeps the surrounding quotes: strip them ("C:\\Program Files\\x.exe" -> C:\\Program Files\\x.exe)
        parts = [p[1:-1] if len(p) >= 2 and p[0] == p[-1] and p[0] in "\"'" else p for p in parts]
    return parts


def resolve_command(cmd: str) -> list[str] | None:
    argv = split_command(cmd)
    if not argv:
        return None
    exe = argv[0]
    found = shutil.which(exe) or (exe if Path(exe).is_file() else None)
    if not found:
        # Called as `.venv\\Scripts\\claimcheck.exe` WITHOUT activating the venv: its Scripts/bin folder is not on PATH,
        # yet mitmdump (installed by the same `pip install .[capture]`) sits right next to the running interpreter.
        for d in {Path(sys.executable).parent, Path(sys.prefix) / "Scripts", Path(sys.prefix) / "bin"}:
            for name in (exe, exe + ".exe"):
                cand = d / name
                if cand.is_file():
                    found = str(cand)
                    break
            if found:
                break
    return [found, *argv[1:]] if found else None


def tool_version(argv: list[str]) -> str:
    try:
        out = subprocess.run([*argv, "--version"], capture_output=True, text=True, timeout=20)  # noqa: S603  # nosec B603
        text = (out.stdout or out.stderr).strip().splitlines()
        return text[0] if text else "?"
    except Exception as e:  # noqa: BLE001
        return f"error: {e}"


@dataclass
class Alert:
    level: str  # warn | abort
    message: str


class ResourceGuard:
    """Checked periodically during capture. `abort` alerts stop the capture gracefully (data is kept)."""

    def __init__(self, path: Path, min_free_disk_mb: int, min_free_ram_mb: int, max_flows: int):
        self.path = Path(path)
        self.min_disk = min_free_disk_mb
        self.min_ram = min_free_ram_mb
        self.max_flows = max_flows
        self._ram_warned = False

    def snapshot(self) -> dict:
        return {"disk_free_mb": round(free_disk_mb(self.path)), "ram_avail_mb": round(avail_ram_mb())}

    def check(self, flows_so_far: int = 0) -> list[Alert]:
        alerts: list[Alert] = []
        disk = free_disk_mb(self.path)
        if disk < self.min_disk:
            alerts.append(Alert("abort", f"free disk {disk:.0f} MB < min_free_disk_mb {self.min_disk} MB"))
        ram = avail_ram_mb()
        if ram < self.min_ram and not self._ram_warned:
            self._ram_warned = True
            alerts.append(Alert("warn", f"available RAM {ram:.0f} MB < min_free_ram_mb {self.min_ram} MB (close other apps)"))
        if self.max_flows and flows_so_far >= self.max_flows:
            alerts.append(Alert("abort", f"flow count {flows_so_far} reached max_flows {self.max_flows}"))
        return alerts


def doctor_checks(runs_root: Path, mitmdump_cmd: str = "mitmdump", online: bool = False) -> list[Check]:
    checks: list[Check] = []
    v = sys.version_info
    checks.append(Check("python", "OK" if v >= (3, 11) else "FAIL", f"{platform.python_version()} ({sys.executable})",
                        "" if v >= (3, 11) else "Python >= 3.11 is required"))
    checks.append(Check("os", "INFO", f"{platform.system()} {platform.release()} ({platform.machine()})"))
    admin = is_admin()
    checks.append(Check("administrator", "OK" if admin else "WARN", "yes" if admin else "no",
                        "" if admin else "capture.mode=local needs an elevated (Administrator) terminal on Windows"))
    cpus = cpu_count()
    tot, av = total_ram_mb(), avail_ram_mb()
    checks.append(Check("cpu", "OK" if cpus >= 2 else "WARN", f"{cpus} logical cores",
                        "" if cpus >= 2 else "Give the VM at least 2 vCPU"))
    checks.append(Check("ram", "OK" if av >= 2048 else "WARN", f"{tot:.0f} MB total, {av:.0f} MB available",
                        "" if av >= 2048 else "Close other programs / give the VM >= 4 GB (8 GB recommended for Electron apps)"))
    disk = free_disk_mb(runs_root if Path(runs_root).exists() else Path.cwd())
    checks.append(Check("disk", "OK" if disk >= 10240 else ("WARN" if disk >= 2048 else "FAIL"),
                        f"{disk / 1024:.1f} GB free at {runs_root}",
                        "" if disk >= 10240 else "Keep >= 10 GB free: raw captures + cloned repos grow quickly"))
    checks.append(Check("static workers", "INFO", f"recommended static.workers = {recommend_static_workers()}",
                        "Set in the manifest (static.workers). Default 1 is always safe."))
    argv = resolve_command(mitmdump_cmd)
    if argv:
        checks.append(Check("mitmdump", "OK", f"{' '.join(argv)} -> {tool_version(argv)}"))
    else:
        checks.append(Check("mitmdump", "WARN", f"'{mitmdump_cmd}' not found",
                            "pip install \".[capture]\"  (or install mitmproxy and set capture.mitmdump)"))
    git = shutil.which("git")
    checks.append(Check("git", "OK" if git else "WARN", git or "not found",
                        "" if git else "Needed only for sources.repo_url auto-clone; you can clone manually"))
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        if os.environ.get(var):
            checks.append(Check("proxy env", "WARN", f"{var}={os.environ[var]}",
                                "A global proxy can interfere with capture and DNS/CNAME lookups"))
            break
    if online:
        try:
            import requests

            r = requests.head("https://github.com", timeout=8)
            checks.append(Check("internet", "OK", f"github.com -> HTTP {r.status_code}"))
        except Exception as e:  # noqa: BLE001
            checks.append(Check("internet", "WARN", f"unreachable: {type(e).__name__}",
                                "Needed for fetching docs, cloning repos and CNAME lookups"))
    return checks
