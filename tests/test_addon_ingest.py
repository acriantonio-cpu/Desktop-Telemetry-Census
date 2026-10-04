from __future__ import annotations

import json

from claimcheck.dynamic import addon
from claimcheck.dynamic.importer import har_to_records, import_flows
from claimcheck.dynamic.ingest import ingest_all, ingest_raw_file, record_to_row
from claimcheck.errors import ClaimCheckError
from claimcheck.util import redact_text
from helpers import jsonl_flow

import pytest


def _rec(**kw):
    base = dict(method="POST", scheme="https", host="EU.I.PostHog.com.", port=443, path_qs="/capture/?ip=1&v=3", req_headers={"Content-Type": "application/json; charset=utf-8", "User-Agent": "ua", "Authorization": "x"},
                body=b'{"event":"e","distinct_id":"123e4567-e89b-12d3-a456-426614174000","properties":{"email":"a@b.co","n":1}}',
                status=200, resp_bytes=2, ts=5.0)
    base.update(kw)
    return addon.build_flow_record(**base)


# ------------------------------------------------------------------ addon (pure functions)
def test_flow_record_features_and_privacy():
    r = _rec()
    assert r["host"] == "eu.i.posthog.com" and r["path"] == "/capture/" and r["query_keys"] == ["ip", "v"]
    assert {"event", "distinct_id", "properties", "properties.email"} <= set(r["payload_keys"])
    assert len(r["id_hashes"]) == 1 and "123e4567" not in json.dumps(r)  # raw identifier never stored
    assert "a@b.co" not in r["sample"] and "<email>" in r["sample"] and "<uuid>" in r["sample"]
    assert r["features"]["has_auth"] and r["features"]["is_json"] and r["req_ct"] == "application/json"


def test_same_identifier_gives_same_hash_across_requests():
    assert _rec()["id_hashes"] == _rec(ts=99.0)["id_hashes"]


def test_sample_can_be_disabled_and_is_truncated():
    assert _rec(store_sample=False)["sample"] == ""
    assert _rec(sample_bytes=0)["sample"] == ""
    assert len(_rec(sample_bytes=20)["sample"]) <= 40  # redaction tokens can lengthen slightly


def test_binary_and_form_and_garbage_bodies_never_raise():
    b = _rec(body=bytes(range(256)) * 4, req_headers={"Content-Type": "application/octet-stream"})
    assert b["features"]["binary"] and b["sample"] == ""
    f = _rec(body=b"a=1&b=2&uid=3", req_headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert f["payload_keys"] == ["a", "b", "uid"] and f["features"]["is_form"]
    assert _rec(body=b"{not json", req_headers={"Content-Type": "application/json"})["payload_keys"] == []
    assert _rec(body=None)["req_bytes"] == 0


def test_nested_json_keys_are_bounded():
    deep = {"a": {"b": {"c": {"d": {"e": 1}}}}}
    assert addon.flatten_keys(deep) == ["a", "a.b", "a.b.c", "a.b.c.d"]
    wide = {f"k{i}": i for i in range(500)}
    assert len(addon.flatten_keys(wide)) == addon.MAX_KEYS


def test_addon_redact_stays_in_sync_with_core_util():
    s = "x a@b.co 123e4567-e89b-12d3-a456-426614174000 " + "Z" * 50 + " 99999999999"
    assert addon.redact(s) == redact_text(s)


def test_addon_module_is_self_contained():
    src = open(addon.__file__, encoding="utf-8").read()
    assert "import claimcheck" not in src and "from claimcheck" not in src


# ------------------------------------------------------------------ ingest
def _mk_raw(ctx, name, lines, terminated=True, phase="capture_idle"):
    att = ctx.store.begin_attempt(phase)
    path = ctx.run.raw_dir / name
    data = "\n".join(lines) + ("\n" if terminated else "")
    path.write_text(data, encoding="utf-8")
    rid = ctx.store.register_raw_file(att, phase, f"raw/{name}")
    return att, rid


def _lines(n):
    return [json.dumps({"type": "meta"})] + [json.dumps(jsonl_flow(ts=float(i))) for i in range(n)]


def test_ingest_is_idempotent_and_marks_complete(ctx):
    att, rid = _mk_raw(ctx, "a.jsonl", _lines(5))
    s1 = ingest_all(ctx.store, ctx.run, True, lambda *a: None)
    assert s1[0]["inserted"] == 5 and s1[0]["meta"] == 1
    raw = ctx.store.raw_files()[0]
    assert raw["complete"] == 1 and raw["lines_ingested"] == 6 and raw["sha256"]
    # forcing a re-read of the same file (as after a crash) must not duplicate rows
    again = ingest_raw_file(ctx.store, ctx.run, {**raw, "lines_ingested": 0}, True, lambda *a: None)
    assert again["inserted"] == 0 and ctx.store.counts()["flows"] == 5
    assert ingest_all(ctx.store, ctx.run, True, lambda *a: None) == []  # nothing left


def test_torn_last_line_is_retried_then_discarded(ctx):
    lines = _lines(3)
    att, rid = _mk_raw(ctx, "t.jsonl", lines + ['{"type":"flow","ts":9,"host":"trunc'], terminated=False)
    logs = []
    s = ingest_all(ctx.store, ctx.run, False, lambda lvl, m: logs.append(m))  # writer might still be running
    assert s[0]["inserted"] == 3 and ctx.store.raw_files()[0]["complete"] == 0
    # writer finished: complete the last line -> now it is ingested exactly once
    path = ctx.run.raw_dir / "t.jsonl"
    path.write_text("\n".join(lines) + "\n" + json.dumps(jsonl_flow(ts=9.0)) + "\n", encoding="utf-8")
    s2 = ingest_all(ctx.store, ctx.run, True, lambda *a: None)
    assert s2[0]["inserted"] == 1 and ctx.store.counts()["flows"] == 4
    # final ingest of a permanently torn line skips it with a warning
    _mk_raw(ctx, "u.jsonl", _lines(1) + ['{"broken'], terminated=False)
    s3 = ingest_all(ctx.store, ctx.run, True, lambda lvl, m: logs.append(m))
    assert s3[0]["torn"] == 1 and any("unreadable" in m for m in logs)


def test_bad_lines_and_unknown_types_are_skipped(ctx):
    _mk_raw(ctx, "b.jsonl", [json.dumps(jsonl_flow()), "not json", json.dumps([1, 2]), json.dumps({"type": "something-new"}), "", json.dumps(jsonl_flow(ts=2.0))])
    s = ingest_all(ctx.store, ctx.run, True, lambda *a: None)[0]
    assert s["inserted"] == 2 and s["bad"] == 2 and s["meta"] == 1


def test_missing_raw_file_is_reported_not_fatal(ctx):
    att = ctx.store.begin_attempt("capture_idle")
    ctx.store.register_raw_file(att, "capture_idle", "raw/gone.jsonl")
    msgs = []
    s = ingest_all(ctx.store, ctx.run, True, lambda lvl, m: msgs.append(m))
    assert s[0]["inserted"] == 0 and any("missing" in m for m in msgs)


def test_record_to_row_maps_kinds():
    assert record_to_row({"type": "sni", "host": "H.com", "ts": 1}, 1, 1, 1, "capture_idle")["kind"] == "sni"
    assert record_to_row({"type": "tls_failed", "host": "h", "error": "pinned"}, 1, 1, 1, "capture_idle")["features"]["error"] == "pinned"
    assert record_to_row({"type": "meta"}, 1, 1, 1, "capture_idle") is None


# ------------------------------------------------------------------ HAR import
def _har(entries):
    return {"log": {"entries": entries}}


def test_har_conversion(tmp_path):
    e = {"startedDateTime": "2026-09-19T10:00:00Z", "request": {"method": "POST", "url": "https://eu.i.posthog.com/capture/?v=1", "headers": [{"name": "User-Agent", "value": "x"}],
         "postData": {"mimeType": "application/json", "text": '{"event":"a","distinct_id":"123e4567-e89b-12d3-a456-426614174000"}'}}, "response": {"status": 200, "content": {"size": 5}}}
    recs = har_to_records(_har([e, {"request": {"url": "nourl"}}]))
    assert len(recs) == 1 and recs[0]["host"] == "eu.i.posthog.com" and recs[0]["payload_keys"] == ["event", "distinct_id"]
    assert recs[0]["ts"] > 1e9 and recs[0]["query_keys"] == ["v"]
    with pytest.raises(ClaimCheckError):
        har_to_records({"nope": 1})


def test_import_flows_copies_original_and_never_overwrites(ctx, tmp_path):
    har = tmp_path / "cap.har"
    har.write_text(json.dumps(_har([{"startedDateTime": "2026-09-19T10:00:00Z", "request": {"method": "GET", "url": "https://a.test/x", "headers": []}, "response": {"status": 200, "content": {"size": 1}}}])), encoding="utf-8")
    for _ in range(2):
        att = ctx.store.begin_attempt("capture_use")
        info = import_flows(ctx, "capture_use", har, "har", att, lambda *a: None)
        ctx.store.finish_attempt(att, "done")
        assert sum(s["inserted"] for s in info["ingest"]) == 1
    assert len(list((ctx.run.artifacts_dir / "imports").iterdir())) == 2
    assert len(list(ctx.run.raw_dir.glob("*.jsonl"))) == 2
    assert har.exists()
    with pytest.raises(ClaimCheckError):
        import_flows(ctx, "capture_use", tmp_path / "missing.har", "har", att, lambda *a: None)
    with pytest.raises(ClaimCheckError):
        import_flows(ctx, "capture_use", har, "xml", att, lambda *a: None)
