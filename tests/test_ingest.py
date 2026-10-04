import json

from claimcheck.dynamic.importer import har_to_records, import_flows
from claimcheck.dynamic.ingest import count_lines_fast, ingest_all, ingest_raw_file
from helpers import http_record


def new_raw(ctx, name="idle_x.jsonl", phase="capture_idle"):
    aid = ctx.store.begin_attempt(phase)
    path = ctx.run.raw_dir / name
    path.write_text("", encoding="utf-8")
    rid = ctx.store.register_raw_file(aid, phase, f"raw/{name}")
    return aid, rid, path


def append(path, *records, raw=""):
    with open(path, "a", encoding="utf-8", newline="\n") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
        f.write(raw)


def log_sink(store):
    return lambda lvl, msg: store.log(lvl, msg)


def test_ingest_maps_all_record_types(ctx):
    aid, rid, path = new_raw(ctx)
    append(path, {"type": "meta"}, http_record(), {"type": "sni", "ts": 2.0, "host": "a.example", "sni": "a.example", "port": 443},
           {"type": "tls_failed", "ts": 3.0, "host": "b.example", "error": "unknown ca"}, {"type": "error", "ts": 4.0, "host": "c.example", "error": "refused"},
           {"type": "unknown_type"})
    stats = ingest_all(ctx.store, ctx.run, final=True, log=log_sink(ctx.store))
    assert stats[0]["inserted"] == 4 and stats[0]["meta"] == 2
    rows = ctx.store.select("flows")
    assert {r["kind"] for r in rows} == {"http", "sni", "tls_failed", "error"}
    assert rows[0]["payload_keys"] == ["event", "distinct_id", "properties"]
    assert ctx.store.raw_files()[0]["complete"] == 1


def test_ingest_is_idempotent_and_never_duplicates(ctx):
    aid, rid, path = new_raw(ctx)
    append(path, http_record(), http_record(ts=1001.0))
    for _ in range(3):
        ingest_raw_file(ctx.store, ctx.run, ctx.store.raw_files()[0], final=False, log=log_sink(ctx.store))
    assert ctx.store.counts()["flows"] == 2
    # even if progress bookkeeping is lost, UNIQUE(raw_file_id, raw_line) prevents duplicates
    ctx.store.update_raw_file(rid, lines_ingested=0)
    ingest_raw_file(ctx.store, ctx.run, ctx.store.raw_files()[0], final=True, log=log_sink(ctx.store))
    assert ctx.store.counts()["flows"] == 2


def test_incremental_ingest_picks_up_appended_lines(ctx):
    aid, rid, path = new_raw(ctx)
    append(path, http_record())
    ingest_raw_file(ctx.store, ctx.run, ctx.store.raw_files()[0], final=False, log=log_sink(ctx.store))
    append(path, http_record(ts=1005.0), http_record(ts=1010.0))
    ingest_raw_file(ctx.store, ctx.run, ctx.store.raw_files()[0], final=True, log=log_sink(ctx.store))
    assert ctx.store.counts()["flows"] == 3


def test_torn_last_line_waits_until_writer_is_finished(ctx):
    aid, rid, path = new_raw(ctx)
    append(path, http_record(), raw='{"type":"flow","host":"half')  # crash in the middle of a write
    ingest_raw_file(ctx.store, ctx.run, ctx.store.raw_files()[0], final=False, log=log_sink(ctx.store))
    assert ctx.store.counts()["flows"] == 1 and ctx.store.raw_files()[0]["complete"] == 0
    stats = ingest_raw_file(ctx.store, ctx.run, ctx.store.raw_files()[0], final=True, log=log_sink(ctx.store))
    assert stats["torn"] == 1 and ctx.store.counts()["flows"] == 1 and ctx.store.raw_files()[0]["complete"] == 1


def test_bad_lines_are_skipped_and_reported(ctx):
    aid, rid, path = new_raw(ctx)
    append(path, http_record(), raw="not json\n[1,2]\n\n")
    append(path, http_record(ts=2000.0))
    stats = ingest_all(ctx.store, ctx.run, final=True, log=log_sink(ctx.store))
    assert stats[0]["bad"] == 2 and ctx.store.counts()["flows"] == 2
    assert any("unreadable line" in e["message"] for e in ctx.store.events())


def test_missing_raw_file_is_reported_not_fatal(ctx):
    aid, rid, path = new_raw(ctx)
    path.unlink()
    stats = ingest_all(ctx.store, ctx.run, final=True, log=log_sink(ctx.store))
    assert stats[0]["inserted"] == 0


def test_count_lines_fast(tmp_path):
    p = tmp_path / "f"
    p.write_bytes(b"a\nb\n")
    n, off = count_lines_fast(p)
    assert (n, off) == (2, 4)
    p.write_bytes(b"a\nb\nc\n")
    assert count_lines_fast(p, off) == (1, 6)
    assert count_lines_fast(tmp_path / "missing") == (0, 0)


HAR = {"log": {"entries": [
    {"startedDateTime": "2026-01-02T03:04:05.000Z", "request": {"method": "POST", "url": "https://eu.i.posthog.com/capture/?v=3",
     "headers": [{"name": "Content-Type", "value": "application/json"}], "postData": {"mimeType": "application/json", "text": '{"event":"e","distinct_id":"abc"}'}},
     "response": {"status": 200, "content": {"size": 12}}},
    {"startedDateTime": "bad-date", "request": {"method": "GET", "url": "https://api.demo.app/x", "headers": []}, "response": {"status": 204, "bodySize": -1}},
    {"request": {"method": "GET", "url": "not a url"}, "response": {}}]}}


def test_har_conversion():
    recs = har_to_records(HAR)
    assert len(recs) == 2
    assert recs[0]["host"] == "eu.i.posthog.com" and recs[0]["payload_keys"] == ["event", "distinct_id"] and recs[0]["ts"] > 0
    assert recs[1]["ts"] == 0.0 and recs[1]["resp_bytes"] == 0


def test_har_rejects_non_har():
    import pytest

    from claimcheck.errors import ClaimCheckError
    with pytest.raises(ClaimCheckError):
        har_to_records({"nope": 1})


def test_import_flows_har_and_jsonl_keep_originals(ctx, tmp_path):
    har = tmp_path / "cap.har"
    har.write_text(json.dumps(HAR), encoding="utf-8")
    aid = ctx.store.begin_attempt("capture_use")
    info = import_flows(ctx, "capture_use", har, "har", aid, log_sink(ctx.store))
    assert info["ingest"][0]["inserted"] == 2
    assert list((ctx.run.artifacts_dir / "imports").glob("cap*.har"))
    jl = tmp_path / "x.jsonl"
    jl.write_text(json.dumps(http_record()) + "\n", encoding="utf-8")
    aid2 = ctx.store.begin_attempt("capture_use")
    import_flows(ctx, "capture_use", jl, "jsonl", aid2, log_sink(ctx.store))
    assert ctx.store.counts()["flows"] == 3 and len({r["path"] for r in ctx.store.raw_files()}) == 2
