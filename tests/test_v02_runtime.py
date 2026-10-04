"""0.2.0 regression tests, part 3: runtime behaviour (FM13-FM31, FM39-FM40)."""

from __future__ import annotations

import base64
import gzip
import json
import os
import socket
import sqlite3
import stat
import types
import zipfile

import pytest
from typer.testing import CliRunner

import claimcheck.dynamic.capture as cap
from claimcheck import cli
from claimcheck.dynamic import addon, importer, ingest
from claimcheck.dynamic.ingest import ingest_all, verify_raw_files
from claimcheck.errors import CaptureError, ClaimCheckError, RunError, RunLocked
from claimcheck.manifest import StaticCfg
from claimcheck.models import PARTIAL
from claimcheck.resources import resolve_command
from claimcheck.runs import RunDir, RunLock, _proc_create_time, create_run, resolve_run
from claimcheck.signatures import load_signatures
from claimcheck.static import asar, scanner
from claimcheck.store import Store, StoreError
from helpers import build_asar, jsonl_flow, write_manifest
from test_capture import _capture, _open

runner = CliRunner()


# ================================================================ addon (FM13, FM18, FM21)
class _FH:
    def __init__(self):
        self.lines = []

    def write(self, s):
        self.lines.append(s)

    def flush(self):
        pass


def _flow(raw: bytes, enc: str = "gzip", decoded=b""):
    hdrs = types.SimpleNamespace(items=lambda: [("Content-Type", "application/json"), ("Content-Encoding", enc)])
    req = types.SimpleNamespace(method="POST", scheme="https", pretty_host="a.example", port=443, path="/x", headers=hdrs,
                                raw_content=raw, get_content=lambda strict=False: decoded, timestamp_start=5.0)
    return types.SimpleNamespace(request=req, response=types.SimpleNamespace(status_code=200, raw_content=b"ok"),
                                 client_conn=types.SimpleNamespace(sni="a.example"), error=None)


def _addon(monkeypatch):
    a = addon.ClaimCheckAddon()
    a.fh = _FH()
    opts = {"claimcheck_sample_bytes": 512, "claimcheck_store_sample": True, "claimcheck_canary_suffix": ""}
    monkeypatch.setattr(a, "_opt", lambda n, d=None: opts.get(n, d))
    return a


def test_fm18_gzip_bomb_is_never_fully_decompressed():
    bomb = gzip.compress(b"A" * 100_000_000)
    assert len(bomb) < 200_000
    out, complete, note = addon.decode_body(bomb, "gzip")
    assert len(out) == addon.MAX_PARSE_BYTES and complete is False and "capped" in note


def test_fm18_gzip_bomb_memory_stays_bounded():
    """The point of the fix is RAM, not the output: decompressing everything and truncating afterwards would still hurt."""
    import tracemalloc

    bomb = gzip.compress(b"A" * 150_000_000)
    tracemalloc.start()
    try:
        addon.decode_body(bomb, "gzip")
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 5 * 1024 * 1024, f"peak {peak / 1e6:.0f} MB"


def test_fm18_normal_bodies_and_encodings_decode(monkeypatch):
    payload = json.dumps({"event": "x", "distinct_id": "abc"}).encode()
    assert addon.decode_body(gzip.compress(payload), "gzip") == (payload, True, "")
    import zlib

    assert addon.decode_body(zlib.compress(payload), "deflate")[0] == payload
    assert addon.decode_body(payload, "")[0] == payload
    assert addon.decode_body(b"\x00garbage", "gzip")[2].startswith("body not decodable")
    big = b"x" * (addon.MAX_OTHER_ENC_BYTES + 1)
    assert addon.decode_body(big, "br", fallback=lambda: b"never called")[2].startswith("body not decoded")
    assert addon.decode_body(b"tiny", "br", fallback=lambda: payload)[0] == payload


def test_fm18_record_of_a_bomb_reports_wire_size_not_zero(monkeypatch):
    a = _addon(monkeypatch)
    bomb = gzip.compress(b"A" * 50_000_000)
    a.response(_flow(bomb))
    rec = json.loads(a.fh.lines[0])
    assert rec["req_bytes"] == len(bomb) > 0 and "capped" in rec["features"]["body_note"]


def test_fm18_undecodable_body_still_records_size(monkeypatch):
    a = _addon(monkeypatch)
    a.response(_flow(b"\x1f\x8bnot-really-gzip"))
    rec = json.loads(a.fh.lines[0])
    assert rec["req_bytes"] == len(b"\x1f\x8bnot-really-gzip")


def test_fm21_addon_that_cannot_open_its_output_fails_loudly(monkeypatch, tmp_path):
    a = addon.ClaimCheckAddon()
    monkeypatch.setattr(a, "_opt", lambda n, d=None: str(tmp_path / "no-such-dir" / "out.jsonl"))
    with pytest.raises(RuntimeError, match="cannot open its output file"):
        a.running()


# ================================================================ static scanner (FM39, FM40)
def _opts(sigs):
    return {"sig_payload": sigs.to_payload(), "chunk_bytes": 1 << 20, "max_file_bytes": 1 << 28, "skip_globs": [], "archive_budget": 1 << 30}


def test_fm39_malformed_asar_nodes_are_skipped_not_fatal(tmp_path):
    hdr = json.dumps({"files": {"a.js": 5, "b": {"size": "NaN", "offset": "0"}, "c": {"files": "x"}}}).encode()
    pad = (4 - len(hdr) % 4) % 4
    import struct

    payload = struct.pack("<I", len(hdr)) + hdr + b"\0" * pad
    hp = struct.pack("<I", len(payload)) + payload
    (tmp_path / "x.asar").write_bytes(struct.pack("<II", 4, len(hp)) + hp)
    assert list(asar.iter_entries(tmp_path / "x.asar")) == []
    res = scanner.scan_physical_file((str(tmp_path / "x.asar"), "x.asar", "binary", _opts(load_signatures())))
    assert res["error"] == ""


def test_fm39_any_exception_in_one_file_is_recorded_and_the_scan_continues(tmp_path, monkeypatch):
    (tmp_path / "a.asar").write_bytes(build_asar({"x.txt": b"hi"}))
    monkeypatch.setattr(scanner.asar, "iter_entries", lambda p: (_ for _ in ()).throw(KeyError("boom")))
    res = scanner.scan_physical_file((str(tmp_path / "a.asar"), "a.asar", "binary", _opts(load_signatures())))
    assert "KeyError" in res["error"]


def test_fm39_truncated_zip_is_reported_as_an_error(tmp_path):
    z = tmp_path / "a.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as f:
        f.writestr("x.txt", os.urandom(200_000))
    raw = z.read_bytes()
    z.write_bytes(raw[: len(raw) // 2] + raw[-400:])
    res = scanner.scan_physical_file((str(z), "a.zip", "binary", _opts(load_signatures())))
    assert res["error"] or res["entries"] == 0


def test_fm40_compressed_containers_and_installers_are_reported_as_not_inspected(tmp_path):
    (tmp_path / "app.7z").write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\0" * 100)
    (tmp_path / "Setup-1.2.exe").write_bytes(b"MZ" + b"\0" * (6 * 1024 * 1024))
    (tmp_path / "main.js").write_text("console.log(1)")
    res = scanner.scan_install(tmp_path, load_signatures(), StaticCfg())
    cov = res.coverage
    assert cov["opaque_container_count"] == 2 and sorted(cov["opaque_containers"]) == ["Setup-1.2.exe", "app.7z"]
    assert cov["files_scanned"] == 1


def test_fm40_opaque_containers_make_the_scan_incomplete_for_scoring():
    from claimcheck.scoring.checks import Facts

    assert Facts(static_coverage={"binary": {"opaque_container_count": 1}}).static_gaps()


# ================================================================ store (FM24-FM31)
def test_fm29_expensive_query_is_stopped_and_sandbox_blocks_everything_but_select(tmp_path):
    st = Store(tmp_path / "s.sqlite")
    heavy = "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < 3000) SELECT count(*) FROM c a, c b, c d, c e"
    with pytest.raises(StoreError, match="too expensive"):
        st.query_readonly(heavy, timeout_s=1)
    for bad in ("ATTACH DATABASE '/tmp/x.db' AS x", "SELECT load_extension('x')", "SELECT 1; SELECT 2", "PRAGMA journal_mode=DELETE",
                "WITH x AS (SELECT 1) INSERT INTO meta VALUES('a','b')"):
        with pytest.raises(StoreError):
            st.query_readonly(bad)
    assert st.query_readonly("SELECT ';' AS semi")[1] == [(";",)]  # a ';' inside a string literal is fine
    assert st.query_readonly("PRAGMA table_info(meta)")[1]


def test_fm30_store_errors_are_user_facing_and_corrupt_files_are_explained(tmp_path):
    assert issubclass(StoreError, ClaimCheckError)
    (tmp_path / "bad.sqlite").write_bytes(b"this is not a database" * 100)
    with pytest.raises(StoreError, match="cannot open store") as e:
        Store(tmp_path / "bad.sqlite")
    assert "export" in e.value.hint


def test_fm26_two_stores_never_allocate_the_same_attempt_seq(tmp_path):
    a, b = Store(tmp_path / "s.sqlite"), Store(tmp_path / "s.sqlite")
    ids = [x.begin_attempt("capture_idle") for x in (a, b, a, b)]
    seqs = sorted(r["seq"] for r in a.attempts("capture_idle"))
    assert len(set(ids)) == 4 and seqs == [1, 2, 3, 4]


def test_store_uses_full_synchronous(tmp_path):
    st = Store(tmp_path / "s.sqlite")
    assert st.conn.execute("PRAGMA synchronous").fetchone()[0] == 2


# ================================================================ runs / locks (FM26-FM28)
def _lock_dir(tmp_path):
    d = tmp_path / "runs" / "app" / "r1"
    d.mkdir(parents=True)
    return RunDir(tmp_path / "runs", "app", "r1")


def test_fm26_recycled_pid_does_not_block_the_run_forever(tmp_path):
    rd = _lock_dir(tmp_path)
    live = os.getppid()  # a real, unrelated, live process
    rd.lock_path.write_text(json.dumps({"pid": live, "host": socket.gethostname(), "since": "x", "create_time": (_proc_create_time(live) or 0) + 3600}))
    lock = RunLock(rd).acquire()
    assert lock.reclaimed_from["pid"] == live
    lock.release()


def test_fm26_a_genuinely_live_holder_still_blocks(tmp_path):
    rd = _lock_dir(tmp_path)
    live = os.getppid()
    rd.lock_path.write_text(json.dumps({"pid": live, "host": socket.gethostname(), "since": "x", "create_time": _proc_create_time(live)}))
    with pytest.raises(RunLocked, match="in use by PID"):
        RunLock(rd).acquire()


def test_fm26_lock_from_another_host_is_not_reclaimed_silently(tmp_path, monkeypatch):
    rd = _lock_dir(tmp_path)
    rd.lock_path.write_text(json.dumps({"pid": 4242, "host": "some-other-pc", "since": "x"}))
    with pytest.raises(RunLocked, match="another machine"):
        RunLock(rd).acquire()
    monkeypatch.setenv("CLAIMCHECK_FORCE_UNLOCK", "1")
    lock = RunLock(rd).acquire()
    assert lock.reclaimed_from["host"] == "some-other-pc"
    lock.release()


def test_fm26_new_locks_record_the_process_start_time(tmp_path):
    rd = _lock_dir(tmp_path)
    with RunLock(rd):
        info = json.loads(rd.lock_path.read_text())
    assert info["pid"] == os.getpid() and isinstance(info["create_time"], float)


@pytest.mark.parametrize("bad", ["../other", "..", "a/b", "a\\b", "/etc"])
def test_fm27_run_and_app_names_cannot_escape_the_runs_folder(runs_root, run_dir, bad):
    with pytest.raises(RunError, match="invalid --run"):
        resolve_run(runs_root, run_dir.app_slug, bad)
    with pytest.raises(RunError, match="invalid --app"):
        resolve_run(runs_root, bad, None)


def test_fm27_tampered_latest_pointer_is_ignored(runs_root, run_dir):
    (runs_root / run_dir.app_slug / "LATEST").write_text("../../etc", encoding="utf-8")
    assert resolve_run(runs_root, run_dir.app_slug, None).run_id == run_dir.run_id  # falls back to the newest real folder
    (runs_root / run_dir.app_slug / "LATEST").write_bytes(b"\xff\xfe\x00")
    assert resolve_run(runs_root, run_dir.app_slug, None).run_id == run_dir.run_id


def test_fm28_run_ids_are_utc_zero_padded_and_sortable(runs_root, manifest_file):
    ids = [create_run(runs_root, manifest_file).run_id for _ in range(12)]
    assert ids == sorted(ids) and len(set(ids)) == 12
    assert all(len(i.split("-")) in (2, 3) for i in ids)


def test_fm28_failed_run_creation_leaves_no_folder_and_keeps_latest(runs_root, manifest_file, monkeypatch):
    import claimcheck.runs as R

    good = create_run(runs_root, manifest_file)

    class Boom:
        def __init__(self, *a, **k):
            raise OSError("disk full")

    monkeypatch.setattr(R, "Store", Boom)
    with pytest.raises(OSError, match="disk full"):
        create_run(runs_root, manifest_file)
    app_dir = runs_root / good.app_slug
    assert sorted(p.name for p in app_dir.iterdir() if p.is_dir()) == [good.run_id]
    assert (app_dir / "LATEST").read_text() == good.run_id


def test_fm28_frozen_manifest_is_the_exact_bytes_that_were_validated(runs_root, tmp_path):
    mf = write_manifest(tmp_path / "m.yaml")
    rd = create_run(runs_root, mf)
    assert rd.manifest_path.read_bytes() == mf.read_bytes()


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_run_folders_are_owner_only(run_dir):
    assert stat.S_IMODE(run_dir.path.stat().st_mode) == 0o700


# ================================================================ ingest / importer (FM22-FM25)
def _register(ctx, name, lines: list[bytes]):
    att = ctx.store.begin_attempt("capture_idle")
    path = ctx.run.raw_dir / name
    path.write_bytes(b"".join(lines))
    ctx.store.register_raw_file(att, "capture_idle", path.relative_to(ctx.run.path).as_posix())
    return att, path


def test_fm22_malformed_records_are_skipped_or_coerced_never_fatal(ctx):
    good = json.dumps(jsonl_flow(host="ok.example", ts=1.0)).encode() + b"\n"
    lines = [good,
             b'{"type":"flow","ts":"abc","host":123,"port":"x","req_bytes":"lots","features":[1],"payload_keys":"oops"}\n',
             b'{"type":"flow","ts":NaN,"host":"nan.example"}\n', b'{"type":"flow","ts":Infinity,"host":"inf.example"}\n',
             b"[1,2,3]\n", b"not json\n", b'{"type":"unknown"}\n', good.replace(b"ok.example", b"two.example")]
    att, _ = _register(ctx, "a.jsonl", lines)
    stats = ingest_all(ctx.store, ctx.run, True, lambda *a: None, attempt_id=att)
    rows = ctx.store.select("flows", [att])
    import math

    assert all(math.isfinite(r["ts"]) for r in rows) and {"ok.example", "two.example", "nan.example", "inf.example"} <= {r["host"] for r in rows}
    weird = next(r for r in rows if r["host"] == "")
    assert weird["port"] is None and weird["req_bytes"] == 0 and weird["payload_keys"] == [] and weird["features"] == {}
    assert stats[0]["bad"] == 2


def test_fm24_oversized_line_is_skipped_with_bounded_memory(ctx, monkeypatch):
    monkeypatch.setattr(ingest, "MAX_LINE_BYTES", 1000)
    good = json.dumps(jsonl_flow(host="ok.example")).encode() + b"\n"
    att, _ = _register(ctx, "big.jsonl", [good, b"X" * 50_000 + b"\n", good.replace(b"ok.example", b"two.example")])
    stats = ingest_all(ctx.store, ctx.run, True, lambda *a: None, attempt_id=att)
    assert {r["host"] for r in ctx.store.select("flows", [att])} == {"ok.example", "two.example"} and stats[0]["bad"] == 1


def test_fm25_verify_detects_change_and_missing_files(ctx):
    att, path = _register(ctx, "v.jsonl", [json.dumps(jsonl_flow()).encode() + b"\n"])
    ingest_all(ctx.store, ctx.run, True, lambda *a: None, attempt_id=att)
    assert [r["status"] for r in verify_raw_files(ctx.store, ctx.run)] == ["ok"]
    with open(path, "ab") as f:
        f.write(b'{"type":"flow"}\n')
    assert [r["status"] for r in verify_raw_files(ctx.store, ctx.run)] == ["changed"]
    path.unlink()
    assert [r["status"] for r in verify_raw_files(ctx.store, ctx.run)] == ["missing"]


def test_fm25_verify_command_exit_codes(runs_root, run_dir, ctx):
    att, path = _register(ctx, "v.jsonl", [json.dumps(jsonl_flow()).encode() + b"\n"])
    ingest_all(ctx.store, ctx.run, True, lambda *a: None, attempt_id=att)
    r = runner.invoke(cli.app, ["verify", "--runs-root", str(runs_root)])
    assert r.exit_code == 0 and "verified" in r.output
    path.write_bytes(b"tampered\n")
    r = runner.invoke(cli.app, ["verify", "--runs-root", str(runs_root)])
    assert r.exit_code == 1 and "changed" in r.output


def test_fm23_har_bad_entries_base64_and_form_params():
    b64 = base64.b64encode(json.dumps({"event": "x", "distinct_id": "1"}).encode()).decode()
    har = {"log": {"entries": ["oops", None, 3, {"request": "no"},
                               {"request": {"url": "https://a.example/x", "method": "POST", "postData": {"mimeType": "application/x-www-form-urlencoded",
                                                                                                         "params": [{"name": "event", "value": "x"}, {"name": "distinct_id", "value": "7"}]}}},
                               {"request": {"url": "https://b.example/", "method": "POST", "postData": {"mimeType": "application/json", "encoding": "base64", "text": b64}},
                                "response": "weird"}]}}
    stats = {}
    recs = importer.har_to_records(har, stats=stats)
    assert stats["skipped"] == 4 and [r["host"] for r in recs] == ["a.example", "b.example"]
    assert set(recs[0]["payload_keys"]) == {"distinct_id", "event"} == set(recs[1]["payload_keys"])
    for bad in ({}, {"log": []}, {"log": {"entries": "x"}}, [], None):
        with pytest.raises(ClaimCheckError):
            importer.har_to_records(bad)


def test_fm23_huge_har_is_refused_and_bom_har_is_read(ctx, tmp_path, monkeypatch):
    har = tmp_path / "s.har"
    har.write_bytes(b"\xef\xbb\xbf" + json.dumps({"log": {"entries": [{"request": {"url": "https://a.example/", "method": "GET"}}]}}).encode())
    att = ctx.store.begin_attempt("capture_use")
    info = importer.import_flows(ctx, "capture_use", har, "har", att, lambda *a: None)
    assert sum(s["inserted"] for s in info["ingest"]) == 1
    monkeypatch.setattr(importer, "MAX_HAR_BYTES", 10)
    with pytest.raises(ClaimCheckError, match="limit"):
        importer.import_flows(ctx, "capture_use", har, "har", ctx.store.begin_attempt("capture_use"), lambda *a: None)


# ================================================================ resources (FM19)
def test_fm19_mitmdump_is_found_next_to_the_interpreter_without_activating_the_venv(tmp_path, monkeypatch):
    bindir = tmp_path / "venv" / "bin"
    bindir.mkdir(parents=True)
    tool = bindir / "fake-mitmdump-xyz"
    tool.write_text("#!/bin/sh\n")
    tool.chmod(0o755)
    monkeypatch.setenv("PATH", "")
    monkeypatch.setattr("claimcheck.resources.sys.executable", str(bindir / "python"))
    assert resolve_command("fake-mitmdump-xyz") == [str(tool)]
    assert resolve_command("definitely-not-installed-xyz") is None


# ================================================================ capture (FM14-FM17, FM21)
def test_fm21_a_silent_addon_aborts_the_capture_instead_of_reporting_zero_records(tmp_path, runs_root, monkeypatch):
    monkeypatch.setenv("FAKE_MITM_MODE", "no_addon")
    monkeypatch.setattr(cap, "STARTUP_WAIT_S", 1.0)
    with _open(tmp_path, runs_root) as ctx:
        with pytest.raises(CaptureError, match="addon did not start"):
            _capture(ctx, minutes=0.05)
        assert ctx.store.attempts("capture_idle")[0]["status"] == "failed"
        assert not ctx.store.effective_attempt_ids("capture_idle")


def test_fm14_failed_ingest_is_partial_never_a_clean_done(tmp_path, runs_root, monkeypatch):
    def boom(*a, **k):
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(cap, "ingest_all", boom)
    with _open(tmp_path, runs_root) as ctx:
        res = _capture(ctx, minutes=0.04)
        assert res.status == PARTIAL and "ingest failed" in res.note and "claimcheck ingest" in res.note
        assert ctx.store.raw_files(only_incomplete=True)  # the raw data is still registered for recovery


def test_fm15_a_suspended_machine_makes_the_capture_partial(tmp_path, runs_root, monkeypatch):
    monkeypatch.setattr(cap, "SUSPEND_GAP_S", 0.3)  # the loop ticks every 0.5 s, so every tick now looks like a pause
    with _open(tmp_path, runs_root) as ctx:
        res = _capture(ctx, minutes=0.04)
        assert res.status == PARTIAL and "paused/suspended" in res.note and res.summary["pause_gaps_s"]


@pytest.mark.parametrize("minutes", [-1, float("inf"), float("nan")])
def test_capture_rejects_absurd_durations(tmp_path, runs_root, minutes):
    with _open(tmp_path, runs_root) as ctx:
        with pytest.raises(CaptureError, match="--minutes"):
            _capture(ctx, minutes=minutes)


def test_fm16_second_ctrl_c_during_cleanup_is_ignored():
    import signal

    before = signal.getsignal(signal.SIGINT)
    with cap._ignore_sigint():
        assert signal.getsignal(signal.SIGINT) == signal.SIG_IGN
    assert signal.getsignal(signal.SIGINT) == before


def test_fm16_mitmdump_that_cannot_be_started_does_not_leak_the_log_handle(tmp_path, runs_root, monkeypatch):
    def nope(*a, **k):
        raise PermissionError("denied")

    monkeypatch.setattr(cap.subprocess, "Popen", nope)
    with _open(tmp_path, runs_root) as ctx:
        with pytest.raises(CaptureError, match="cannot start mitmdump"):
            _capture(ctx, minutes=0.05)
        log = next(ctx.run.logs_dir.glob("mitmdump_*.log"))
        log.unlink()  # would raise PermissionError on Windows if the handle were still open


# ================================================================ CLI (FM30, export)
def test_fm30_database_errors_are_explained_not_dumped(monkeypatch):
    def locked():
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(cli, "app", locked)
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert e.value.code == 2


def test_fm30_broken_pipe_is_silent(monkeypatch):
    monkeypatch.setattr(cli, "app", lambda: (_ for _ in ()).throw(BrokenPipeError()))
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert e.value.code == 0


def test_fm25_export_never_follows_symlinks_and_never_contains_itself(runs_root, run_dir, tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP SECRET")
    try:
        (run_dir.path / "artifacts" / "link").symlink_to(secret)
    except OSError:
        pytest.skip("symlinks not available")
    out = run_dir.path / "inside.zip"  # a target INSIDE the run folder: must not include itself
    r = runner.invoke(cli.app, ["export", "--runs-root", str(runs_root), "--out", str(out)])
    assert r.exit_code == 0, r.output
    with zipfile.ZipFile(out) as z:
        names = z.namelist()
        assert not any(n.endswith("link") or n.endswith("inside.zip") for n in names)
        assert not any(b"TOP SECRET" in z.read(n) for n in names)
    assert "keep it private" in r.output
