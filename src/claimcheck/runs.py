"""Run folders: create / list / resolve / lock.

Layout:  <runs_root>/<app_slug>/<run_id>/
            manifest.yaml   frozen copy (editable: changes apply to FUTURE phases, hash logged per attempt)
            run.json        metadata
            store.sqlite    all results (append-only)
            raw/            raw capture files (JSONL) - never overwritten
            logs/           claimcheck.log + mitmdump logs
            artifacts/      cloned repo, cached documents, imports
            reports/        report_<n>.html / .json (never overwritten)
         <runs_root>/<app_slug>/LATEST   pointer to the most recent run id
"""

from __future__ import annotations

import json
import os
import platform
import socket
import sys
from dataclasses import dataclass
import shutil
from datetime import UTC, datetime
from pathlib import Path

import psutil
import yaml

from claimcheck import __version__
from claimcheck.errors import RunError, RunLocked
from claimcheck.manifest import Manifest, load_manifest, parse_manifest_bytes
from claimcheck.store import Store
from claimcheck.util import atomic_write_text, is_safe_name, sha256_file, utcnow_iso


@dataclass
class RunDir:
    root: Path  # runs root
    app_slug: str
    run_id: str

    @property
    def path(self) -> Path:
        return self.root / self.app_slug / self.run_id

    @property
    def manifest_path(self) -> Path:
        return self.path / "manifest.yaml"

    @property
    def store_path(self) -> Path:
        return self.path / "store.sqlite"

    @property
    def raw_dir(self) -> Path:
        return self.path / "raw"

    @property
    def logs_dir(self) -> Path:
        return self.path / "logs"

    @property
    def artifacts_dir(self) -> Path:
        return self.path / "artifacts"

    @property
    def reports_dir(self) -> Path:
        return self.path / "reports"

    @property
    def lock_path(self) -> Path:
        return self.path / "run.lock"

    def ensure_dirs(self) -> None:
        for d in (self.raw_dir, self.logs_dir, self.artifacts_dir, self.reports_dir):
            d.mkdir(parents=True, exist_ok=True)


def create_run(runs_root: Path, manifest_path: Path, label: str = "") -> RunDir:
    """Create a NEW run folder for the app in `manifest_path`. Never reuses or overwrites a folder.

    The manifest is read ONCE: what was validated is byte-for-byte what gets frozen. `LATEST` is updated only after the
    run is fully initialised, and a half-built folder is removed, so a failure never leaves a broken 'latest' behind.
    """
    manifest_path = Path(manifest_path)
    if not manifest_path.is_file():
        load_manifest(manifest_path)  # raises the usual clear ManifestError
    raw = manifest_path.read_bytes()
    manifest = parse_manifest_bytes(raw, manifest_path.resolve().parent)
    runs_root = Path(runs_root)
    app_dir = runs_root / manifest.app.slug
    app_dir.mkdir(parents=True, exist_ok=True)
    base = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")  # UTC: local time is non-monotonic across DST changes
    run_id, n = base, 1
    while True:
        try:
            (app_dir / run_id).mkdir()  # atomic: fails if it exists
            break
        except FileExistsError:
            n += 1
            run_id = f"{base}-{n:03d}"  # zero-padded: lexicographic order == creation order
    rd = RunDir(runs_root, manifest.app.slug, run_id)
    try:
        if os.name == "posix":
            os.chmod(rd.path, 0o700)  # raw captures may hold personal data: owner only
        rd.ensure_dirs()
        rd.manifest_path.write_bytes(raw)  # frozen copy (byte-exact)
        meta = {
            "schema": 1,
            "app_slug": manifest.app.slug,
            "run_id": run_id,
            "label": label,
            "created_at": utcnow_iso(),
            "tool_version": __version__,
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "hostname": socket.gethostname(),
            "manifest_source": str(manifest_path.resolve()),
            "manifest_base": str(manifest_path.resolve().parent),
            "manifest_sha256_at_init": sha256_file(rd.manifest_path),
        }
        atomic_write_text(rd.path / "run.json", json.dumps(meta, indent=2, ensure_ascii=False))
        with Store(rd.store_path) as st:
            st.set_meta("created_at", meta["created_at"])
            st.set_meta("tool_version", __version__)
            st.log("INFO", f"run created: {rd.path}")
    except BaseException:
        shutil.rmtree(rd.path, ignore_errors=True)
        raise
    atomic_write_text(app_dir / "LATEST", run_id)
    return rd


def _read_latest(app_dir: Path) -> str:
    """LATEST is a plain file anyone may edit or a crash may truncate: only a safe single folder name is ever trusted."""
    try:
        v = (app_dir / "LATEST").read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return ""
    return v if is_safe_name(v) else ""


def list_apps(runs_root: Path) -> list[str]:
    runs_root = Path(runs_root)
    if not runs_root.is_dir():
        return []
    return sorted(p.name for p in runs_root.iterdir() if p.is_dir() and any(c.is_dir() for c in p.iterdir()))


def list_runs(runs_root: Path, app: str | None = None) -> list[dict]:
    out = []
    for slug in ([app] if app else list_apps(runs_root)):
        app_dir = Path(runs_root) / slug
        if not app_dir.is_dir():
            continue
        latest = _read_latest(app_dir)
        for p in sorted(app_dir.iterdir()):
            if not (p.is_dir() and (p / "store.sqlite").exists()):
                continue
            meta = {}
            if (p / "run.json").exists():
                try:
                    meta = json.loads((p / "run.json").read_text(encoding="utf-8"))
                except ValueError:
                    meta = {}
            out.append({
                "app": slug, "run_id": p.name, "created_at": meta.get("created_at", ""),
                "label": meta.get("label", ""), "latest": p.name == latest, "path": str(p),
            })
    return out


def resolve_run(runs_root: Path, app: str | None, run: str | None) -> RunDir:
    """Pick a run. `app` may be omitted if there is exactly one app; `run` defaults to latest."""
    runs_root = Path(runs_root)
    apps = list_apps(runs_root)
    if not apps:
        raise RunError(f"No runs found under {runs_root}", hint="Create one with: claimcheck init apps/<app>.yaml")
    for label_, value in (("--app", app), ("--run", run)):
        if value and value != "latest" and not is_safe_name(value):
            raise RunError(f"invalid {label_} value {value!r}: it must be a plain folder name (no path separators or '..')")
    if app is None:
        if len(apps) > 1:
            raise RunError(f"Several apps exist ({', '.join(apps)}); choose one with --app", hint="claimcheck runs")
        app = apps[0]
    app_dir = runs_root / app
    if not app_dir.is_dir():
        raise RunError(f"Unknown app '{app}'. Known: {', '.join(apps)}")
    if not run or run == "latest":
        run_id = _read_latest(app_dir)
        if not run_id or not (app_dir / run_id).is_dir():
            cands = sorted(p.name for p in app_dir.iterdir() if p.is_dir())
            if not cands:
                raise RunError(f"App '{app}' has no runs")
            run_id = cands[-1]
    else:
        run_id = run
        if not (app_dir / run_id).is_dir():
            known = sorted(p.name for p in app_dir.iterdir() if p.is_dir())
            raise RunError(f"Run '{run_id}' not found for app '{app}'. Known: {', '.join(known)}")
    return RunDir(runs_root, app, run_id)


def set_latest(rd: RunDir) -> None:
    atomic_write_text(rd.root / rd.app_slug / "LATEST", rd.run_id)


def _proc_create_time(pid: int) -> float | None:
    try:
        return psutil.Process(pid).create_time()
    except (psutil.Error, OSError, ValueError):
        return None


class RunLock:
    """Exclusive lock file so two processes cannot write the same run.

    A stale lock (dead PID, or a PID that the OS has since recycled for an unrelated process - checked with the process
    start time) is reclaimed. A lock written on ANOTHER host (run folder on a share / synced drive) cannot be verified and
    is never reclaimed silently: set CLAIMCHECK_FORCE_UNLOCK=1 once you are sure the other process is gone.
    """

    def __init__(self, rd: RunDir):
        self.rd = rd
        self.acquired = False
        self.reclaimed_from: dict | None = None

    def _payload(self) -> str:
        return json.dumps({"pid": os.getpid(), "host": socket.gethostname(), "since": utcnow_iso(),
                           "create_time": _proc_create_time(os.getpid())})

    @staticmethod
    def _holder_alive(info: dict) -> bool:
        pid = info.get("pid")
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            return False
        if pid == os.getpid() or not psutil.pid_exists(pid):
            return False
        recorded = info.get("create_time")
        if isinstance(recorded, (int, float)):
            actual = _proc_create_time(pid)
            if actual is None or abs(actual - recorded) > 2.0:
                return False  # same PID, different process: the PID was recycled (e.g. after a reboot)
        return True

    def acquire(self) -> RunLock:
        path = self.rd.lock_path
        for _ in range(2):
            try:
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(self._payload())
                self.acquired = True
                return self
            except FileExistsError:
                info = {}
                try:
                    info = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    pass
                pid = info.get("pid")
                same_host = info.get("host") == socket.gethostname()
                if same_host and self._holder_alive(info):
                    raise RunLocked(
                        f"Run is in use by PID {pid} (since {info.get('since')}).",
                        hint="Wait for it to finish (or close the other terminal).",
                    ) from None
                if info and not same_host and os.environ.get("CLAIMCHECK_FORCE_UNLOCK") != "1":
                    raise RunLocked(
                        f"Run is locked by another machine ({info.get('host')}, PID {pid}, since {info.get('since')}).",
                        hint="If that process is really gone, delete run.lock or set CLAIMCHECK_FORCE_UNLOCK=1.",
                    ) from None
                # stale (dead PID, recycled PID, same PID) or explicitly forced -> reclaim
                self.reclaimed_from = info
                try:
                    path.unlink()
                except OSError:
                    raise RunLocked(f"Cannot remove stale lock {path}") from None
        raise RunLocked(f"Cannot acquire lock {path}")

    def release(self) -> None:
        if self.acquired:
            try:
                self.rd.lock_path.unlink()
            except OSError:
                pass
            self.acquired = False

    def __enter__(self):
        return self.acquire()

    def __exit__(self, *exc):
        self.release()


def load_run_manifest(rd: RunDir) -> Manifest:
    """Load the frozen manifest; relative paths resolve against the ORIGINAL manifest folder (run.json)."""
    base = None
    try:
        base = json.loads((rd.path / "run.json").read_text(encoding="utf-8")).get("manifest_base")
    except (OSError, ValueError):
        pass
    return load_manifest(rd.manifest_path, base=Path(base) if base else None)


def manifest_hash(rd: RunDir) -> str:
    return sha256_file(rd.manifest_path)


def dump_manifest(rd: RunDir, data: dict) -> None:  # pragma: no cover - convenience for tooling
    atomic_write_text(rd.manifest_path, yaml.safe_dump(data, sort_keys=False, allow_unicode=True))
