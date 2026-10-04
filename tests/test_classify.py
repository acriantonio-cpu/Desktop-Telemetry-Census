from __future__ import annotations

import pytest

from claimcheck.classify.blocklists import Blocklist, load_blocklists
from claimcheck.classify.dnsutil import resolve_cname_chain
from claimcheck.classify.engine import classify_flows
from claimcheck.manifest import parse_manifest
from claimcheck.models import (
    L_ALLOWED, L_FIRST_PARTY, L_OPAQUE, L_SUSPECT, L_TELEMETRY_1P, L_TELEMETRY_3P, L_UNKNOWN,
)
from claimcheck.signatures import load_signatures
from helpers import telemetry_flows

SIGS = load_signatures()


def _m(**kw):
    d = {"app": {"name": "X", "exe_name": "x.exe"}, "first_party_domains": ["x.app"], "allowed_domains": ["updates.x.app"], "classify": {"resolve_cname": False}}
    d.update(kw)
    return parse_manifest(d)


def _cls(flows, manifest=None, bl=None, resolver=None):
    labels, dns = classify_flows(flows, manifest or _m(), SIGS, bl or Blocklist(), resolver, lambda *a: None)
    return {(x["capture_phase"], x["host"]): x for x in labels}, dns


def _f(host, phase="capture_idle", kind="http", method="GET", path="/", ts=1000.0, **kw):
    d = {"capture_phase": phase, "host": host, "kind": kind, "method": method, "path": path, "ts": ts, "req_bytes": 0, "payload_keys": [], "id_hashes": []}
    d.update(kw)
    return d


def test_known_vendor_domain_is_third_party_telemetry_even_without_payload():
    res, _ = _cls([_f("o1.ingest.sentry.io", kind="sni")])
    x = res[("capture_idle", "o1.ingest.sentry.io")]
    assert x["label"] == L_TELEMETRY_3P and x["sdk_id"] == "sentry" and x["category"] == "crash_reporting"
    assert any("vendor" in r for r in x["reasons"])


def test_behavioural_detection_of_unknown_collector():
    res, _ = _cls(telemetry_flows(6, host="collector.unknown-analytics.net"))
    x = res[("capture_idle", "collector.unknown-analytics.net")]
    assert x["label"] == L_TELEMETRY_3P and x["sdk_id"] is None
    reasons = " ".join(x["reasons"])
    for needle in ("telemetry-shaped keys", "persistent hashed identifier", "periodic beacon", "small POSTs", "telemetry endpoint"):
        assert needle in reasons


def test_ordinary_api_traffic_is_not_flagged():
    flows = [_f("api.github.com", method="GET", path="/repos/x/y", ts=1000 + i * 7.3) for i in range(8)]
    res, _ = _cls(flows)
    assert res[("capture_idle", "api.github.com")]["label"] == L_UNKNOWN


def test_first_party_labels_and_first_party_telemetry():
    flows = [_f("api.x.app", path="/v1/me")] + telemetry_flows(6, host="events.x.app")
    res, _ = _cls(flows)
    assert res[("capture_idle", "api.x.app")]["label"] == L_FIRST_PARTY
    assert res[("capture_idle", "events.x.app")]["label"] == L_TELEMETRY_1P


def test_allowed_domain_suppresses_heuristics_but_not_vendor_match():
    flows = telemetry_flows(6, host="updates.x.app")
    res, _ = _cls(flows)
    x = res[("capture_idle", "updates.x.app")]
    assert x["label"] == L_ALLOWED and x["score"] == 0.0 and any("ignored" in r for r in x["reasons"])
    m = _m(allowed_domains=["sentry.io"])
    res2, _ = _cls([_f("o1.ingest.sentry.io")], manifest=m)
    assert res2[("capture_idle", "o1.ingest.sentry.io")]["label"] == L_TELEMETRY_3P
    assert any("NOT suppressed" in r for r in res2[("capture_idle", "o1.ingest.sentry.io")]["reasons"])


def test_suspect_band_between_thresholds():
    flows = [_f("api.foo.io", method="POST", path="/v1/events", ts=1000 + i * 13.7, req_bytes=100 + i * 300, payload_keys=["event", "properties", "timestamp"]) for i in range(3)]
    res, _ = _cls(flows)
    assert res[("capture_idle", "api.foo.io")]["label"] == L_SUSPECT


def test_opaque_pinned_traffic_labels():
    res, _ = _cls([_f("pinned.example.org", kind="tls_failed", ts=1000 + i * 60) for i in range(5)])
    x = res[("capture_idle", "pinned.example.org")]
    assert x["label"] == L_OPAQUE and any("not inspectable" in r for r in x["reasons"])
    res2, _ = _cls([_f("o1.ingest.sentry.io", kind="tls_failed")])
    assert res2[("capture_idle", "o1.ingest.sentry.io")]["label"] == L_TELEMETRY_3P  # SNI is enough for vendors


def test_persistent_id_across_hosts_counts():
    flows = [_f("a.foo.io", method="POST", id_hashes=["h1"]), _f("b.bar.io", method="POST", id_hashes=["h1"])]
    res, _ = _cls(flows)
    assert any("persistent" in r for r in res[("capture_idle", "a.foo.io")]["reasons"])


def test_phases_are_classified_separately():
    flows = telemetry_flows(6, phase="capture_idle") + [_f("api.x.app", phase="capture_optout")]
    res, _ = _cls(flows)
    assert ("capture_idle", "eu.i.posthog.com") in res and ("capture_optout", "eu.i.posthog.com") not in res


def test_blocklist_hit_and_formats(tmp_path):
    hosts = tmp_path / "hosts.txt"
    hosts.write_text("# c\n0.0.0.0 ads.tracker.net\n0.0.0.0 adnet.example.net\n127.0.0.1 localhost\n||adguard.example.org^\nplain-domain.com\n", encoding="utf-8")
    disc = tmp_path / "services.json"
    disc.write_text('{"categories":{"Analytics":[{"Co":{"http://co.com/":["metrics.co.com"]}}],"Content":[{"X":{"http://x.com/":["skipme.com"]}}]}}', encoding="utf-8")
    bl = load_blocklists([str(hosts), str(disc), str(tmp_path / "nope.txt")], include_default_dir=False)
    for h in ("ads.tracker.net", "x.adguard.example.org", "plain-domain.com", "a.metrics.co.com"):
        assert bl.match(h), h
    assert not bl.match("skipme.com") and not bl.match("safe.org")
    # a blocklist hit alone (0.60) lands in the "suspect" band: it needs one more signal to reach telemetry (0.70)
    res, _ = _cls([_f("cdn.adnet.example.net")], bl=bl)
    x = res[("capture_idle", "cdn.adnet.example.net")]
    assert x["label"] == L_SUSPECT and any("blocklist" in r for r in x["reasons"])
    # ...and a telemetry-like word in the host name is such an extra signal (0.60 + 0.15)
    res2, _ = _cls([_f("cdn.ads.tracker.net")], bl=bl)
    assert res2[("capture_idle", "cdn.ads.tracker.net")]["label"] == L_TELEMETRY_3P


def test_cname_cloaking_detected_and_cached():
    calls = []

    def resolver(host):
        calls.append(host)
        return (["o1.ingest.sentry.io"], "") if host == "metrics.x.app" else ([], "")

    m = _m(classify={"resolve_cname": True})
    flows = [_f("metrics.x.app"), _f("metrics.x.app", ts=1001), _f("api.x.app")]
    res, dns = _cls(flows, manifest=m, resolver=resolver)
    x = res[("capture_idle", "metrics.x.app")]
    assert x["label"] == L_TELEMETRY_1P and x["sdk_id"] == "sentry" and any("CNAME cloaking" in r for r in x["reasons"])
    assert calls.count("metrics.x.app") == 1 and {d["host"] for d in dns} == {"metrics.x.app", "api.x.app"}
    assert res[("capture_idle", "api.x.app")]["label"] == L_FIRST_PARTY


def test_dns_lookup_budget_is_respected():
    m = _m(classify={"resolve_cname": True, "max_dns_lookups": 2})
    flows = [_f(f"h{i}.x.app") for i in range(6)]
    calls = []
    _cls(flows, manifest=m, resolver=lambda h: (calls.append(h) or [], ""))
    assert len(calls) == 2


def test_cname_resolver_handles_missing_dnspython_and_errors(monkeypatch):
    chain, err = resolve_cname_chain("nonexistent.invalid", timeout=0.5)
    assert isinstance(chain, list) and isinstance(err, str)


@pytest.mark.parametrize("bad", [{"host": ""}, {"host": None, "sni": ""}])
def test_flows_without_host_are_ignored(bad):
    res, _ = _cls([{**_f("x.com"), **bad}])
    assert res == {}
