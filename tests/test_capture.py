from __future__ import annotations

import os
import stat
import sys
import time
from pathlib import Path

import psutil
import pytest

import claimcheck.dynamic.capture as cap
from claimcheck.context import open_context
from claimcheck.errors import CaptureError
from claimcheck.manifest import CaptureCfg
from claimcheck.pipeline import recover_orphans, run_phase
from claimcheck.resources import split_command
from claimcheck.runs import create_run
from helpers import write_manifest

FAKE = str(Path(__file__).parent / "fake_mitmdump.py")


def _open(tmp_path, runs_root, capture=None, **extra):
    capture = {"mitmdump": f'"{sys.executable}" "{FAKE}"', "mode": "regular", "heartbeat_seconds": 0.5, **(capture or {})}
    mf = write_manifest(tmp_path / f"m{time.time_ns()}.yaml", capture=capture, **extra)
    rd = create_run(runs_root, mf)
    return open_context(runs_root, rd.app_slug, rd.run_id)


def _capture(ctx, phase="capture_idle", **kw):
    return run_phase(ctx, phase, lambda a: cap.run_capture(ctx, a, phase, **kw))


def test_build_command_modes():
    argv = ["mitmdump"]
    local = cap.build_command(argv, CaptureCfg(mode="local"), "app.exe", Path("out.jsonl"), Path("addon.py"))
    assert local[:3] == ["mitmdump", "-s", "addon.py"] and "local:app.exe" in local and "--listen-port" not in local
    reg = cap.build_command(argv, CaptureCfg(mode="regular", listen_port=9999, canary_suffix="a.test"), "x", Path("o"), Path("a"))
    assert "9999" in reg and "claimcheck_canary_suffix=a.test" in reg and not any(x.startswith("local:") for x in reg)
    assert "claimcheck_out=o" in reg and "claimcheck_store_sample=true" in reg


def test_split_command_handles_quotes():
    assert split_command('"/usr/bin/python3" "/a b/c.py" --x') == ["/usr/bin/python3", "/a b/c.py", "--x"]
    assert split_command("") == []


def test_full_capture_with_fake_proxy(tmp_path, runs_root):
    with _open(tmp_path, runs_root) as ctx:
        res = _capture(ctx, minutes=0.06)
        assert res.status == "done" and res.summary["records_inserted"] >= 3
        raw = ctx.store.raw_files()[0]
        assert raw["complete"] == 1 and raw["path"].startswith("raw/idle_")
        assert ctx.store.counts()["flows"] == res.summary["records_inserted"]
        assert (ctx.run.logs_dir / res.summary["mitmdump_log"]).exists()
        assert ctx.store.effective_attempt_ids("capture_idle")


def test_second_capture_adds_a_new_file_and_keeps_the_first(tmp_path, runs_root):
    with _open(tmp_path, runs_root) as ctx:
        _capture(ctx, minutes=0.04)
        n1 = ctx.store.counts()["flows"]
        _capture(ctx, minutes=0.04)
        files = sorted(p.name for p in ctx.run.raw_dir.glob("idle_*.jsonl"))
        assert len(files) == 2 and ctx.store.counts()["flows"] > n1
        assert len(ctx.store.effective_attempt_ids("capture_idle")) == 2


def test_startup_failure_reports_log_tail_and_marks_failed(tmp_path, runs_root, monkeypatch):
    monkeypatch.setenv("FAKE_MITM_MODE", "exit_early")
    with _open(tmp_path, runs_root) as ctx:
        with pytest.raises(CaptureError, match="simulated startup failure"):
            _capture(ctx, minutes=0.05)
        assert ctx.store.attempts("capture_idle")[0]["status"] == "failed"
        assert not ctx.store.effective_attempt_ids("capture_idle")


def test_ctrl_c_is_graceful_and_data_is_kept(tmp_path, runs_root, monkeypatch):
    real_sleep, calls = time.sleep, {"n": 0}

    def sleeper(s):
        calls["n"] += 1
        if calls["n"] == 12:
            raise KeyboardInterrupt
        real_sleep(min(s, 0.1))

    with _open(tmp_path, runs_root) as ctx:
        monkeypatch.setattr(cap.time, "sleep", sleeper)
        res = _capture(ctx, minutes=5)  # planned 5 min, user stops after ~2 s
        monkeypatch.undo()
        assert res.status == "partial" and "early" in res.note and res.summary["records_inserted"] >= 1
        assert ctx.store.effective_attempt_ids("capture_idle")  # partial data still counts

    with _open(tmp_path, runs_root) as ctx2:  # 'use' phase with no planned end: Ctrl+C is the normal way to finish
        calls["n"] = 0
        monkeypatch.setattr(cap.time, "sleep", sleeper)
        res2 = _capture(ctx2, "capture_use", minutes=0)
        monkeypatch.undo()
        assert res2.status == "done" and res2.summary["stopped_by_user"]


def test_max_flows_guard_stops_capture_safely(tmp_path, runs_root):
    with _open(tmp_path, runs_root, capture={"max_flows": 3}) as ctx:
        res = _capture(ctx, minutes=1)
        assert res.status == "partial" and "max_flows" in res.note and res.summary["records_inserted"] >= 1


def test_not_enough_disk_refuses_to_start(tmp_path, runs_root):
    with _open(tmp_path, runs_root, capture={"min_free_disk_mb": 10**9}) as ctx:
        with pytest.raises(CaptureError, match="not enough resources"):
            _capture(ctx, minutes=0.05)
        assert not list(ctx.run.raw_dir.iterdir())  # nothing half-created


def test_local_mode_needs_admin_and_exe_name(tmp_path, runs_root, monkeypatch):
    monkeypatch.setattr(cap, "is_admin", lambda: False)
    with _open(tmp_path, runs_root, capture={"mode": "local"}) as ctx:
        with pytest.raises(CaptureError, match="elevated"):
            _capture(ctx, minutes=0.05)
        res = _capture(ctx, minutes=0.05, allow_no_admin=True)
        assert res.status == "done"
    with _open(tmp_path, runs_root, capture={"mode": "local"}, app={"name": "NoExe", "exe_name": ""}) as ctx2:
        monkeypatch.setattr(cap, "is_admin", lambda: True)
        with pytest.raises(CaptureError, match="exe_name"):
            _capture(ctx2, minutes=0.05)


def test_missing_mitmdump_gives_actionable_error(tmp_path, runs_root):
    with _open(tmp_path, runs_root, capture={"mitmdump": "definitely-not-installed-xyz"}) as ctx:
        with pytest.raises(CaptureError) as e:
            _capture(ctx, minutes=0.05)
        assert "not found" in str(e.value) and "capture" in e.value.hint


def test_launch_requires_exe_path_and_app_is_killed_at_end(tmp_path, runs_root):
    with _open(tmp_path, runs_root) as ctx, pytest.raises(CaptureError, match="exe_path"):
        _capture(ctx, minutes=0.05, launch=True)
    if os.name == "nt":
        pytest.skip("shell script launcher is POSIX only")
    script = tmp_path / "fakeapp.sh"
    script.write_text("#!/bin/sh\nsleep 60\n", encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    with _open(tmp_path, runs_root, app={"name": "L", "exe_name": "fakeapp", "exe_path": str(script)}) as ctx2:
        res = _capture(ctx2, minutes=0.05, launch=True)
        assert res.status == "done"
        time.sleep(0.3)
        assert not [p for p in psutil.process_iter(["cmdline"]) if p.info["cmdline"] and str(script) in " ".join(p.info["cmdline"])]


def test_recovery_after_hard_crash_ingests_raw_file_without_duplicates(tmp_path, runs_root):
    """Simulate: capture process is killed after writing data but before ingest."""
    mf = write_manifest(tmp_path / "m.yaml")
    rd = create_run(runs_root, mf)
    with open_context(runs_root, rd.app_slug, rd.run_id) as ctx:
        att = ctx.store.begin_attempt("capture_idle")  # left 'running' = crash
        raw = ctx.run.raw_dir / "idle_001_1.jsonl"
        good = '{"type":"flow","ts":1,"host":"eu.i.posthog.com","method":"POST","path":"/capture/","req_bytes":10}\n'
        raw.write_text('{"type":"meta"}\n' + good * 3 + '{"type":"flow","ts":2,"ho', encoding="utf-8")  # torn last line
        ctx.store.register_raw_file(att, "capture_idle", "raw/idle_001_1.jsonl")
    with open_context(runs_root, rd.app_slug, rd.run_id) as ctx2:
        assert ctx2.store.attempts("capture_idle")[0]["status"] == "interrupted"
        assert recover_orphans(ctx2) == 3
        assert ctx2.store.attempts("capture_idle")[0]["status"] == "partial"  # promoted: data exists
        assert ctx2.store.effective_attempt_ids("capture_idle")
        assert recover_orphans(ctx2) == 0 and ctx2.store.counts()["flows"] == 3  # idempotent
