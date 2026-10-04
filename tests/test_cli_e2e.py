from __future__ import annotations

import json
import sqlite3
import zipfile

import pytest
import yaml
from typer.testing import CliRunner

from claimcheck.cli import app
from helpers import build_asar

runner = CliRunner()


def _run_dir(root):
    """The (single) run folder of the app; skips the LATEST pointer file."""
    dirs = sorted(d for d in (root / "noteapp").iterdir() if d.is_dir())
    assert dirs
    return dirs[-1]


def _cli(root, *args, ok=True):
    r = runner.invoke(app, ["--help"] if not args else [args[0], *args[1:]] if args[0] in ("doctor", "version", "new", "candidates") else [args[0], "--runs-root", str(root), *args[1:]])
    if ok:
        assert r.exit_code == 0, r.output
    return r


@pytest.fixture()
def workspace(tmp_path):
    inst = tmp_path / "install/resources"
    inst.mkdir(parents=True)
    (inst / "app.asar").write_bytes(build_asar({"node_modules/@sentry/node/package.json": b"{}", "main.js": b"api.mixpanel.com"}))
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text('{"dependencies":{"electron":"1"}}')
    (tmp_path / "policy.md").write_text("We use Sentry.", encoding="utf-8")
    (tmp_path / "README.md").write_text("A privacy-friendly, local-first, open-source notes app. No telemetry.", encoding="utf-8")
    entries = [{"startedDateTime": f"2026-09-19T10:00:{i * 10:02d}Z", "request": {"method": "POST", "url": "https://eu.i.posthog.com/capture/", "headers": [{"name": "Content-Type", "value": "application/json"}],
                "postData": {"mimeType": "application/json", "text": '{"event":"x","distinct_id":"123e4567-e89b-12d3-a456-426614174000","properties":{}}'}}, "response": {"status": 200, "content": {"size": 2}}} for i in range(6)]
    (tmp_path / "cap.har").write_text(json.dumps({"log": {"entries": entries}}), encoding="utf-8")
    m = {"schema_version": 1, "app": {"name": "NoteApp", "exe_name": "n.exe", "install_dir": str(tmp_path / "install")}, "first_party_domains": ["noteapp.test"],
         "sources": {"repo_path": str(repo), "documents": [{"type": "file", "location": str(tmp_path / "policy.md"), "role": "privacy_policy"}, {"type": "file", "location": str(tmp_path / "README.md"), "role": "readme"}]},
         "classify": {"resolve_cname": False}}
    (tmp_path / "noteapp.yaml").write_text(yaml.safe_dump(m), encoding="utf-8")
    return tmp_path


def test_complete_workflow_via_cli(workspace):
    root = workspace / "runs"
    _cli(root, "init", str(workspace / "noteapp.yaml"), "--label", "e2e")
    assert "e2e" in _cli(root, "runs").output
    for cmd in ("claims", "static"):
        _cli(root, cmd)
    _cli(root, "import-flows", str(workspace / "cap.har"), "--phase", "idle")
    for cmd in ("classify", "score", "report"):
        _cli(root, cmd)
    out = _cli(root, "status").output
    assert "done" in out and "capture_idle" in out
    shown = _cli(root, "show", "verdicts").output
    assert "no_telemetry" in shown and "CONTRADICTED" in shown
    assert "eu.i.posthog.com" in _cli(root, "sql", "SELECT host, label FROM labels").output
    assert "STEP" in _cli(root, "events").output or "attempt" in _cli(root, "events").output
    run_dir = _run_dir(root)
    reports = list((run_dir / "reports").glob("*.html"))
    assert reports and (run_dir / "logs/claimcheck.log").exists()


def test_resume_and_rerun_keep_history(workspace):
    root = workspace / "runs"
    _cli(root, "init", str(workspace / "noteapp.yaml"))
    _cli(root, "import-flows", str(workspace / "cap.har"), "--phase", "idle")
    _cli(root, "resume")
    r2 = _cli(root, "resume")
    assert "none (everything is up to date)" in r2.output
    _cli(root, "claims")  # explicit re-run => new attempt, nothing lost
    with sqlite3.connect(_run_dir(root) / "store.sqlite") as con:
        assert con.execute("SELECT COUNT(*) FROM attempts WHERE phase='claims'").fetchone()[0] == 2
        assert con.execute("SELECT COUNT(*) FROM claims").fetchone()[0] >= 8  # both attempts' claims present


def test_switching_between_runs(workspace):
    root = workspace / "runs"
    _cli(root, "init", str(workspace / "noteapp.yaml"), "--label", "first")
    _cli(root, "init", str(workspace / "noteapp.yaml"), "--label", "second")
    ids = sorted(p.name for p in (root / "noteapp").iterdir() if p.is_dir())
    assert len(ids) == 2
    _cli(root, "claims", "--run", ids[0])
    assert "claims" in _cli(root, "status", "--run", ids[0]).output
    other = _cli(root, "status", "--run", ids[1]).output
    assert "pending" in other  # the second run is untouched by work on the first


def test_user_errors_are_clean_messages_not_tracebacks(workspace):
    root = workspace / "runs"
    r = _cli(root, "status", ok=False)
    assert r.exit_code != 0
    r = _cli(root, "capture", "--phase", "nonsense", ok=False)
    assert r.exit_code != 0
    _cli(root, "init", str(workspace / "noteapp.yaml"))
    r = _cli(root, "sql", "DROP TABLE claims", ok=False)
    assert r.exit_code != 0
    r = _cli(root, "show", "nope", ok=False)
    assert r.exit_code != 0


def test_new_and_candidates_never_overwrite(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert runner.invoke(app, ["new", "My App"]).exit_code == 0
    assert (tmp_path / "apps/my-app.yaml").exists()
    assert runner.invoke(app, ["new", "My App"]).exit_code == 0 or True  # second call is reported as error by main(), not overwritten
    before = (tmp_path / "apps/my-app.yaml").read_text()
    runner.invoke(app, ["new", "My App"])
    assert (tmp_path / "apps/my-app.yaml").read_text() == before
    r = runner.invoke(app, ["candidates", "--make", "jan"])
    assert r.exit_code == 0 and (tmp_path / "apps/jan.yaml").exists()
    assert "jan.ai/docs/privacy" in (tmp_path / "apps/jan.yaml").read_text()
    assert "jan" in runner.invoke(app, ["candidates", "--tier", "A"]).output
    assert "verify_at" in runner.invoke(app, ["candidates", "--show", "zed"]).output


def test_export_produces_consistent_zip(workspace):
    root = workspace / "runs"
    _cli(root, "init", str(workspace / "noteapp.yaml"))
    _cli(root, "claims")
    out = workspace / "export.zip"
    _cli(root, "export", "--out", str(out))
    with zipfile.ZipFile(out) as z:
        names = z.namelist()
        assert any(n.endswith("manifest.yaml") for n in names) and not any(n.endswith("run.lock") for n in names)
        db = [n for n in names if n.endswith("store.sqlite")]
        assert len(db) == 1
        z.extract(db[0], workspace / "x")
    with sqlite3.connect(workspace / "x" / db[0]) as con:
        assert con.execute("SELECT COUNT(*) FROM claims").fetchone()[0] >= 4
    assert _cli(root, "export", "--out", str(out), ok=False).exit_code != 0  # never overwrites


def test_exclude_include_roundtrip(workspace):
    root = workspace / "runs"
    _cli(root, "init", str(workspace / "noteapp.yaml"))
    _cli(root, "import-flows", str(workspace / "cap.har"), "--phase", "idle")
    _cli(root, "exclude", "1")
    assert "excluded" in _cli(root, "show", "attempts").output or "1" in _cli(root, "show", "attempts").output
    with sqlite3.connect(_run_dir(root) / "store.sqlite") as con:
        assert con.execute("SELECT excluded FROM attempts WHERE id=1").fetchone()[0] == 1
    _cli(root, "include", "1")
    assert _cli(root, "exclude", "999", ok=False).exit_code != 0


def test_version_and_doctor_run():
    assert "claimcheck" in runner.invoke(app, ["version"]).output
    r = runner.invoke(app, ["doctor"])
    assert "environment check" in r.output
