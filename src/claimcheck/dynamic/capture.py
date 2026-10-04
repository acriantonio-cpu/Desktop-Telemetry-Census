"""Dynamic capture: run mitmdump + our addon, guard resources, stop cleanly, ingest what was captured.

Guarantees:
* the raw JSONL is opened in append mode and flushed per record => a crash/kill loses at most one line;
* on Ctrl+C / disk-full / RAM alarm / mitmdump crash we still stop the proxy and ingest everything;
* raw files are never overwritten (unique names) and tracked in `raw_files` for later re-ingest.
"""

from __future__ import annotations

import contextlib
import math
import os
import signal
import subprocess  # argv lists only, never shell=True; commands come from the user's own manifest  # nosec B404
import time
from pathlib import Path

import psutil

from claimcheck.context import Context
from claimcheck.dynamic import addon as addon_module
from claimcheck.dynamic.ingest import count_lines_fast, ingest_all
from claimcheck.errors import CaptureError
from claimcheck.models import CAPTURE_SHORT, DONE, FAILED, PARTIAL, PhaseResult
from claimcheck.resources import ResourceGuard, is_admin, resolve_command
from claimcheck.ui import ui
from claimcheck.util import human_bytes, human_duration, unique_path

INSTRUCTIONS = {
    "capture_idle": "IDLE phase: start the app (or let claimcheck launch it) and DO NOT touch it. We measure what it sends by itself.",
    "capture_use": "USE phase: use the app normally (open it, create/edit content, change a setting...). Press Ctrl+C here when you are done.",
    "capture_optout": "OPT-OUT phase: FIRST disable telemetry/analytics/crash reports in the app's settings, THEN use it (or leave it idle).",
}


SUSPEND_GAP_S = 15.0  # the loop ticks every 0.5 s: a longer gap means the machine was suspended / frozen / the clock jumped
STARTUP_WAIT_S = 25.0


@contextlib.contextmanager
def _ignore_sigint():
    """While saving data a second Ctrl+C must not abort the cleanup (it would orphan mitmdump and skip the ingest)."""
    try:
        old = signal.signal(signal.SIGINT, signal.SIG_IGN)
    except (ValueError, OSError):  # not the main thread
        yield
        return
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, old)


def addon_path() -> Path:
    return Path(addon_module.__file__).resolve()


def build_command(argv: list[str], cfg, exe_name: str, out_path: Path, addon: Path) -> list[str]:
    cmd = [*argv, "-s", str(addon), "--set", f"claimcheck_out={out_path}",
           "--set", f"claimcheck_sample_bytes={int(cfg.payload_sample_bytes)}",
           "--set", f"claimcheck_store_sample={'true' if cfg.store_payload_sample else 'false'}",
           "--set", "termlog_verbosity=warn", "--set", "flow_detail=0"]
    if cfg.canary_suffix:
        # canary hosts are answered locally and may not even resolve: never contact them upstream
        cmd += ["--set", f"claimcheck_canary_suffix={cfg.canary_suffix}", "--set", "upstream_cert=false", "--set", "connection_strategy=lazy"]
    if cfg.mode == "local":
        cmd += ["--mode", f"local:{exe_name}"]
    else:
        cmd += ["--listen-host", "127.0.0.1", "--listen-port", str(cfg.listen_port)]
    cmd += [str(x) for x in (cfg.extra_args or [])]
    return cmd


def _stop_process(proc: subprocess.Popen, grace: float = 10.0) -> None:
    if proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            proc.send_signal(signal.CTRL_BREAK_EVENT)  # type: ignore[attr-defined]
        else:
            proc.send_signal(signal.SIGINT)
        proc.wait(timeout=grace)
        return
    except (subprocess.TimeoutExpired, OSError, ValueError):
        pass
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except (subprocess.TimeoutExpired, OSError):
        proc.kill()


def _terminate_tree(pid: int) -> None:
    try:
        parent = psutil.Process(pid)
    except psutil.Error:
        return
    procs = parent.children(recursive=True) + [parent]
    for p in procs:
        try:
            p.terminate()
        except psutil.Error:
            pass
    _, alive = psutil.wait_procs(procs, timeout=5)
    for p in alive:
        try:
            p.kill()
        except psutil.Error:
            pass


def _tail(path: Path, n: int = 15) -> str:
    try:
        return "\n".join(path.read_text(encoding="utf-8", errors="replace").splitlines()[-n:])
    except OSError:
        return ""


def run_capture(ctx: Context, attempt_id: int, phase: str, minutes: float | None = None, launch: bool | None = None,
                allow_no_admin: bool = False) -> PhaseResult:
    cfg = ctx.manifest.capture
    app = ctx.manifest.app
    short = CAPTURE_SHORT[phase]
    planned_min = {"capture_idle": cfg.idle_minutes, "capture_use": cfg.use_minutes, "capture_optout": cfg.optout_minutes}[phase]
    if minutes is not None:
        if not math.isfinite(minutes) or minutes < 0:
            raise CaptureError(f"--minutes must be a finite number >= 0 (0 = until Ctrl+C), got {minutes!r}")
        planned_min = minutes
    launch = cfg.launch_app if launch is None else launch

    # ---- preconditions (fail early, with an actionable hint) -------------
    argv = resolve_command(cfg.mitmdump)
    if not argv:
        raise CaptureError(f"mitmdump not found ('{cfg.mitmdump}')", hint='Install it: pip install ".[capture]"  (see docs/02-installation.md)')
    if cfg.mode == "local":
        if not app.exe_name:
            raise CaptureError("capture.mode=local needs app.exe_name (process image name, e.g. MyApp.exe)")
        if not is_admin() and not allow_no_admin:
            raise CaptureError("local capture needs elevated privileges", hint="Open an Administrator terminal (Windows) / use sudo, or pass --allow-no-admin to try anyway.")
    if launch and not app.exe_path:
        raise CaptureError("launch requested but app.exe_path is empty")

    guard = ResourceGuard(ctx.run.path, cfg.min_free_disk_mb, cfg.min_free_ram_mb, cfg.max_flows)
    snap = guard.snapshot()
    pre = guard.check(0)
    if any(a.level == "abort" for a in pre):
        raise CaptureError("not enough resources to start: " + "; ".join(a.message for a in pre), hint="Free disk space (see docs/06-hardware-resources.md)")
    for a in pre:
        ui.warn(a.message)

    seq = len(ctx.store.raw_files(attempt_id=attempt_id)) + 1
    raw_path = unique_path(ctx.run.raw_dir, f"{short}_{attempt_id:03d}_{seq}", ".jsonl")
    raw_path.touch(exist_ok=False)
    rel = raw_path.relative_to(ctx.run.path).as_posix()
    ctx.store.register_raw_file(attempt_id, phase, rel)
    ctx.run.logs_dir.mkdir(parents=True, exist_ok=True)
    mlog_path = unique_path(ctx.run.logs_dir, f"mitmdump_{short}_{attempt_id:03d}", ".log")

    cmd = build_command(argv, cfg, app.exe_name, raw_path, addon_path())
    ui.info(INSTRUCTIONS[phase])
    ui.info(f"resources at start: disk free {snap['disk_free_mb']} MB, RAM available {snap['ram_avail_mb']} MB")
    ui.verbose("mitmdump command: " + " ".join(cmd))
    if cfg.mode == "regular":
        ui.info(f"regular proxy mode: point the app to http://127.0.0.1:{cfg.listen_port} "
                f"(PowerShell: $env:HTTPS_PROXY='http://127.0.0.1:{cfg.listen_port}'; $env:HTTP_PROXY=$env:HTTPS_PROXY) and trust the mitmproxy CA")

    flags = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}  # type: ignore[attr-defined]
    mlog = open(mlog_path, "ab")  # noqa: SIM115
    try:
        proc = subprocess.Popen(cmd, stdout=mlog, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, **flags)  # noqa: S603  # nosec B603
    except OSError as e:
        mlog.close()
        raise CaptureError(f"cannot start mitmdump: {e}", hint="Check capture.mitmdump in the manifest and run `claimcheck doctor`.") from e
    app_proc: subprocess.Popen | None = None
    stopped_by_user = False
    abort_reason = ""
    started_mono = time.monotonic()  # wall-clock can jump (NTP, VM restore): durations use the monotonic clock
    flows_seen, offset = 0, 0
    gaps: list[float] = []
    ingest_error = ""
    status, note = DONE, ""
    try:
        # ---- wait for the addon to be alive (meta line written) ------------
        ui.info("starting mitmdump ...")
        t0 = time.monotonic()
        while time.monotonic() - t0 < STARTUP_WAIT_S:
            if proc.poll() is not None:
                raise CaptureError(f"mitmdump exited immediately (code {proc.returncode}). Last log lines:\n{_tail(mlog_path)}",
                                   hint=f"Full log: {mlog_path}")
            if raw_path.stat().st_size > 0:
                break
            time.sleep(0.3)
        else:
            # mitmdump is up but our addon never wrote its 'meta' line: NOTHING is being recorded. Continuing would produce a
            # "successful" capture with 0 records, i.e. a false "the app is silent".
            raise CaptureError(f"the claimcheck addon did not start within {STARTUP_WAIT_S:.0f} s (nothing would be recorded). Last log lines:\n{_tail(mlog_path)}",
                               hint=f"Full log: {mlog_path}. Check the mitmproxy version (`claimcheck doctor`) and that the output folder is writable.")
        ui.ok(f"mitmdump running (PID {proc.pid}); raw file: {rel}")

        if launch:
            try:
                app_proc = subprocess.Popen([app.exe_path], cwd=str(Path(app.exe_path).parent), stdin=subprocess.DEVNULL,  # noqa: S603  # nosec B603
                                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except OSError as e:
                raise CaptureError(f"cannot launch the app: {e}", hint="Check app.exe_path (an installer-elevated app may need to be started by hand).") from e
            ui.ok(f"launched app (PID {app_proc.pid})")

        end_at = started_mono + planned_min * 60 if planned_min > 0 else None
        ui.info(f"capturing for {planned_min:g} min (Ctrl+C to stop early)" if end_at else "capturing until you press Ctrl+C")
        last_hb = 0.0
        prev_wall, prev_mono = time.time(), time.monotonic()
        try:
            while True:
                now = time.monotonic()
                wall = time.time()
                gap = max(wall - prev_wall, now - prev_mono)
                if gap > SUSPEND_GAP_S:
                    gaps.append(round(gap, 1))
                    ui.warn(f"the system was paused/suspended (or the clock jumped) for ~{gap:.0f} s: this capture window is NOT continuous")
                prev_wall, prev_mono = wall, now
                if end_at and now >= end_at:
                    break
                if proc.poll() is not None:
                    status, note = FAILED, f"mitmdump exited unexpectedly (code {proc.returncode})"
                    ui.error(note + "\n" + _tail(mlog_path))
                    break
                if now - last_hb >= max(1.0, cfg.heartbeat_seconds):
                    last_hb = now
                    new, offset = count_lines_fast(raw_path, offset)
                    flows_seen += new
                    snap = guard.snapshot()
                    remaining = f"/{human_duration(planned_min * 60)}" if end_at else ""
                    raw_size = 0
                    with contextlib.suppress(OSError):
                        raw_size = raw_path.stat().st_size
                    ui.plain(f"  [{short}] {human_duration(now - started_mono)}{remaining}  records={max(0, flows_seen - 1)}  "
                             f"raw={human_bytes(raw_size)}  disk_free={snap['disk_free_mb']} MB  ram_avail={snap['ram_avail_mb']} MB")
                    for a in guard.check(flows_seen):
                        if a.level == "abort":
                            abort_reason = a.message
                        else:
                            ui.warn(a.message)
                    if abort_reason:
                        ui.error(f"stopping capture safely: {abort_reason}")
                        break
                time.sleep(0.5)
        except KeyboardInterrupt:
            stopped_by_user = True
            ui.warn("Ctrl+C received: stopping capture and saving data ...")
    finally:
        with _ignore_sigint():
            if app_proc is not None and cfg.kill_app_at_end:
                _terminate_tree(app_proc.pid)
            _stop_process(proc)
            mlog.close()
            stats = []
            for attempt in range(2):
                try:
                    stats = ingest_all(ctx.store, ctx.run, final=True, log=lambda lvl, m: ui.warn(m) if lvl == "WARN" else ui.verbose(m), attempt_id=attempt_id)
                    ingest_error = ""
                    break
                except Exception as e:  # noqa: BLE001 - never lose the raw file: it stays registered for `claimcheck ingest`
                    ingest_error = f"{type(e).__name__}: {e}"
                    ui.error(f"ingest failed (attempt {attempt + 1}): {e}. Raw data is safe in {rel}; run `claimcheck ingest`.")

    inserted = sum(s["inserted"] for s in stats)
    duration = time.monotonic() - started_mono
    if status == FAILED and inserted > 0:
        status = PARTIAL
    if ingest_error:
        # the raw file is complete but was NOT fully ingested: never report a clean DONE (0 records would read as "silent app").
        # PARTIAL keeps the attempt usable: `claimcheck ingest` adds the missing records under the SAME attempt.
        status, note = PARTIAL, f"ingest failed ({ingest_error[:120]}); run `claimcheck ingest`"
    if abort_reason:
        status, note = PARTIAL, f"stopped: {abort_reason}"
    elif stopped_by_user and end_at is not None and duration < 0.9 * planned_min * 60:
        status, note = PARTIAL, f"stopped early by user after {human_duration(duration)} of {human_duration(planned_min * 60)}"
    if gaps and status == DONE:
        status, note = PARTIAL, f"system paused/suspended {len(gaps)} time(s) (~{sum(gaps):.0f} s): observation window not continuous"
    if inserted == 0 and status == DONE:
        ui.warn("0 records captured. Check: app name (exe_name), CA trusted, app really used the network. See docs/07-debugging-and-troubleshooting.md")
    summary = {"duration_s": round(duration, 1), "records_inserted": inserted, "raw_file": rel, "mitmdump_log": mlog_path.name,
               "planned_minutes": planned_min, "mode": cfg.mode, "stopped_by_user": stopped_by_user, "pause_gaps_s": gaps}
    ui.ok(f"capture {short}: {inserted} records in {human_duration(duration)} -> status {status}")
    return PhaseResult(status=status, summary=summary, note=note)
