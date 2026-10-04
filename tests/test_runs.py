from __future__ import annotations

import json
import os
import subprocess
import sys
import time

import pytest

from claimcheck.context import open_context
from claimcheck.errors import RunError, RunLocked
from claimcheck.runs import RunLock, create_run, list_apps, list_runs, resolve_run
from claimcheck.store import Store
from helpers import write_manifest


def test_create_run_layout_and_frozen_manifest(runs_root, manifest_file):
    rd = create_run(runs_root, manifest_file, label="first")
    for d in ("raw", "logs", "artifacts", "reports"):
        assert (rd.path / d).is_dir()
    assert rd.manifest_path.read_bytes() == manifest_file.read_bytes()
    meta = json.loads((rd.path / "run.json").read_text())
    assert meta["label"] == "first" and meta["app_slug"] == "testapp"
    assert (runs_root / "testapp" / "LATEST").read_text() == rd.run_id
    with Store(rd.store_path) as st:
        assert st.get_meta("tool_version")


def test_runs_never_overwrite_each_other(runs_root, manifest_file):
    ids = {create_run(runs_root, manifest_file).run_id for _ in range(4)}
    assert len(ids) == 4  # even created within the same second
    assert len(list_runs(runs_root, "testapp")) == 4


def test_resolve_latest_explicit_and_errors(runs_root, manifest_file, tmp_path):
    a = create_run(runs_root, manifest_file)
    b = create_run(runs_root, manifest_file)
    assert resolve_run(runs_root, None, None).run_id == b.run_id
    assert resolve_run(runs_root, "testapp", a.run_id).run_id == a.run_id  # switch back to an older run
    with pytest.raises(RunError, match="not found"):
        resolve_run(runs_root, "testapp", "nope")
    with pytest.raises(RunError, match="Unknown app"):
        resolve_run(runs_root, "other", None)
    create_run(runs_root, write_manifest(tmp_path / "b.yaml", app={"name": "Other", "exe_name": "o.exe"}))
    assert list_apps(runs_root) == ["other", "testapp"]
    with pytest.raises(RunError, match="Several apps"):
        resolve_run(runs_root, None, None)


def test_resolve_with_no_runs(runs_root):
    with pytest.raises(RunError, match="No runs"):
        resolve_run(runs_root, None, None)


def test_lock_blocks_live_process_and_reclaims_stale(run_dir):
    sleeper = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])  # noqa: S603
    try:
        import socket

        run_dir.lock_path.write_text(json.dumps({"pid": sleeper.pid, "host": socket.gethostname(), "since": "x"}))
        with pytest.raises(RunLocked):
            RunLock(run_dir).acquire()
    finally:
        sleeper.kill()
        sleeper.wait()
    time.sleep(0.2)
    lock = RunLock(run_dir).acquire()  # holder is dead now -> stale lock reclaimed
    assert lock.reclaimed_from and lock.reclaimed_from["pid"] == sleeper.pid
    lock.release()
    assert not run_dir.lock_path.exists()


def test_lock_released_after_context_even_on_error(runs_root, run_dir):
    with pytest.raises(ZeroDivisionError), open_context(runs_root, run_dir.app_slug, run_dir.run_id):
        assert run_dir.lock_path.exists()
        1 / 0  # noqa: B018
    assert not run_dir.lock_path.exists()


def test_readonly_open_does_not_take_lock(runs_root, run_dir):
    with open_context(runs_root, run_dir.app_slug, run_dir.run_id, write=False):
        assert not run_dir.lock_path.exists()


def test_crash_leaves_interrupted_attempt_and_next_open_recovers(runs_root, run_dir):
    with open_context(runs_root, run_dir.app_slug, run_dir.run_id) as c:
        c.store.begin_attempt("capture_idle")  # simulate: process dies while running
    os.remove(run_dir.lock_path) if run_dir.lock_path.exists() else None
    with open_context(runs_root, run_dir.app_slug, run_dir.run_id) as c2:
        att = c2.store.attempts("capture_idle")[0]
        assert att["status"] == "interrupted"


def test_journal_persists_to_log_file_and_events(ctx):
    ctx.journal("WARN", "something odd")
    ctx.journal("DEBUG", "very detailed")
    log = (ctx.run.logs_dir / "claimcheck.log").read_text()
    assert "something odd" in log and "very detailed" in log
    msgs = [e["message"] for e in ctx.store.events(50)]
    assert "something odd" in msgs and "very detailed" not in msgs  # DEBUG stays out of the DB


def test_relative_paths_resolve_against_original_manifest_folder_not_run_folder(tmp_path, runs_root):
    """Regression: the manifest is copied into the run folder, but relative paths must keep pointing at the original location."""
    import yaml

    from claimcheck.runs import load_run_manifest

    (tmp_path / "apps").mkdir()
    (tmp_path / "inst").mkdir()
    (tmp_path / "doc.md").write_text("No telemetry.", encoding="utf-8")
    mf = tmp_path / "apps" / "rel.yaml"
    mf.write_text(yaml.safe_dump({"app": {"name": "Rel", "exe_name": "r.exe", "install_dir": "../inst"},
                                  "sources": {"documents": [{"type": "file", "location": "../doc.md", "role": "readme"}]}}), encoding="utf-8")
    rd = create_run(runs_root, mf)
    m = load_run_manifest(rd)
    assert m.app.install_dir == str((tmp_path / "apps" / ".." / "inst").resolve()) or m.app.install_dir.endswith("inst")
    from pathlib import Path

    assert Path(m.app.install_dir).is_dir() and Path(m.sources.documents[0].location).is_file()
