import json
import sys
import types

from claimcheck.dynamic import addon


def rec(**kw):
    base = dict(method="POST", scheme="https", host="EU.i.posthog.com", port=443, path_qs="/capture/?v=3&ip=1", req_headers={"Content-Type": "application/json", "User-Agent": "ua"},
                body=b'{"event":"x","distinct_id":"123e4567-e89b-12d3-a456-426614174000","properties":{"email":"a@b.co","$os":"win"}}',
                status=200, resp_bytes=5, ts=1.0)
    base.update(kw)
    return addon.build_flow_record(**base)


def test_structure_is_kept_values_are_not():
    r = rec()
    assert r["host"] == "eu.i.posthog.com" and r["path"] == "/capture/" and r["query_keys"] == ["ip", "v"]
    assert {"event", "distinct_id", "properties", "properties.email"} <= set(r["payload_keys"])
    assert len(r["id_hashes"]) == 1 and "123e4567" not in json.dumps(r)
    assert "a@b.co" not in r["sample"] and "<email>" in r["sample"] and "<uuid>" in r["sample"]


def test_same_identifier_gives_same_hash_across_requests():
    a, b = rec(), rec(body=b'{"other":"123E4567-E89B-12D3-A456-426614174000"}')
    assert a["id_hashes"] == b["id_hashes"]


def test_sample_can_be_disabled_or_limited():
    assert rec(store_sample=False)["sample"] == ""
    assert len(rec(sample_bytes=20)["sample"]) <= 40
    assert rec(sample_bytes=0)["sample"] == ""


def test_binary_and_empty_bodies_never_raise():
    assert rec(body=b"\x00\x01\xff\xfe" * 100, req_headers={"Content-Type": "application/octet-stream"})["features"]["binary"] is True
    assert rec(body=None)["req_bytes"] == 0
    assert rec(body=b"{broken json", req_headers={"Content-Type": "application/json"})["payload_keys"] == []


def test_form_and_query_identifiers():
    r = rec(req_headers={"Content-Type": "application/x-www-form-urlencoded"}, body=b"tid=UA-1&cid=555&t=event", path_qs="/collect?uid=123e4567-e89b-12d3-a456-426614174000")
    assert r["features"]["is_form"] and {"tid", "cid", "t"} <= set(r["payload_keys"]) and r["id_hashes"]


def test_flatten_keys_limits_depth_and_size():
    deep = {"a": {"b": {"c": {"d": {"e": 1}}}}}
    assert "a.b.c" in addon.flatten_keys(deep) and "a.b.c.d.e" not in addon.flatten_keys(deep)
    assert len(addon.flatten_keys({f"k{i}": 1 for i in range(500)})) <= addon.MAX_KEYS
    assert addon.flatten_keys({"items": [{"x": 1}, {"y": 2}]}) == ["items", "items[].x", "items[].y"]


def test_auth_and_cookie_only_recorded_as_booleans():
    r = rec(req_headers={"Authorization": "Bearer SECRET", "Cookie": "s=1", "Content-Type": "application/json"})
    assert r["features"]["has_auth"] and r["features"]["has_cookie"] and "SECRET" not in json.dumps(r)


def test_error_records_carry_reason():
    r = rec(kind="error", error="boom", status=None)
    assert r["type"] == "error" and r["error"] == "boom"


class FakeFH:
    def __init__(self):
        self.lines = []

    def write(self, s):
        self.lines.append(s)

    def flush(self):
        pass


def make_addon(monkeypatch, options=None):
    a = addon.ClaimCheckAddon()
    a.fh = FakeFH()
    opts = {"claimcheck_sample_bytes": 512, "claimcheck_store_sample": True, "claimcheck_canary_suffix": "", **(options or {})}
    monkeypatch.setattr(a, "_opt", lambda name, default=None: opts.get(name, default))
    return a


def fake_flow(host="a.example", body=b"{}"):
    hdrs = types.SimpleNamespace(items=lambda: [("Content-Type", "application/json")])
    req = types.SimpleNamespace(method="POST", scheme="https", pretty_host=host, port=443, path="/x", headers=hdrs,
                                get_content=lambda strict=False: body, timestamp_start=5.0)
    resp = types.SimpleNamespace(status_code=200, raw_content=b"ok")
    return types.SimpleNamespace(request=req, response=resp, client_conn=types.SimpleNamespace(sni=host), error=None)


def test_addon_hooks_write_one_json_line_each(monkeypatch):
    a = make_addon(monkeypatch)
    a.response(fake_flow())
    f = fake_flow()
    f.error = types.SimpleNamespace(msg="connection refused")
    f.response = None
    a.error(f)
    a.tls_clienthello(types.SimpleNamespace(client_hello=types.SimpleNamespace(sni="x.example"), context=types.SimpleNamespace(server=types.SimpleNamespace(address=("1.2.3.4", 443)))))
    a.tls_failed_client(types.SimpleNamespace(conn=types.SimpleNamespace(sni="pinned.example", error="unknown ca"), context=types.SimpleNamespace(server=types.SimpleNamespace(address=("1.2.3.4", 443)))))
    types_written = [json.loads(x)["type"] for x in a.fh.lines]
    assert types_written == ["flow", "error", "sni", "tls_failed"]
    assert all(x.endswith("\n") for x in a.fh.lines)


def test_addon_hooks_swallow_exceptions(monkeypatch):
    a = make_addon(monkeypatch)
    a.response(object())  # malformed flow must not raise
    a.error(object())
    a.tls_clienthello(object())
    a.tls_failed_client(object())
    a.request(object())
    # nothing raised into mitmproxy, but the failures are NOT silent: each leaves an addon_error trace
    kinds = [json.loads(x)["type"] for x in a.fh.lines]
    assert kinds == ["addon_error"] * 5
    assert {json.loads(x)["where"] for x in a.fh.lines} == {"response", "error", "tls_clienthello", "tls_failed_client", "request"}


def test_addon_error_traces_are_capped(monkeypatch):
    a = make_addon(monkeypatch)
    for _ in range(addon.ClaimCheckAddon.MAX_ERROR_RECORDS + 30):
        a.response(object())
    assert len(a.fh.lines) == addon.ClaimCheckAddon.MAX_ERROR_RECORDS and a.errors == addon.ClaimCheckAddon.MAX_ERROR_RECORDS + 30


def test_canary_responder_answers_locally_only_for_matching_hosts(monkeypatch):
    fake_http = types.SimpleNamespace(Response=types.SimpleNamespace(make=lambda code, body, headers: ("resp", code)))
    monkeypatch.setattr(addon, "http", fake_http)
    a = make_addon(monkeypatch, {"claimcheck_canary_suffix": "posthog.com, canary-app.example"})
    hit, miss = fake_flow("eu.i.posthog.com"), fake_flow("real.example.org")
    hit.response = miss.response = None
    a.request(hit)
    a.request(miss)
    assert hit.response == ("resp", 200) and miss.response is None
    a.request(fake_flow("notposthog.com"))  # suffix match is on label boundary


def test_module_importable_without_mitmproxy():
    assert addon.addons and hasattr(addon.addons[0], "response")
    assert "claimcheck" not in " ".join(m for m in sys.modules if m.startswith("mitmproxy"))  # sanity
