"""0.2.0 regression tests, part 2: inputs & configuration (FM11-FM13, FM20, FM32-FM38, FM43)."""

from __future__ import annotations

import json

import pytest
import yaml

from claimcheck import util
from claimcheck.candidates import list_candidates, manifest_text_for
from claimcheck.classify.blocklists import Blocklist, fetch_default_lists, load_blocklists
from claimcheck.classify.engine import classify_flows
from claimcheck.dynamic import addon
from claimcheck.errors import ClaimCheckError, ManifestError
from claimcheck.manifest import load_manifest, parse_manifest, render_template
from claimcheck.signatures import ContentMatcher, _parse_vendor_file, load_signatures


def _m(**kw):
    return parse_manifest({"app": {"name": "X", "exe_name": "x.exe"}, **kw})


# ---------------------------------------------------------------- FM11: shared hosting is not "first party"
@pytest.mark.parametrize("host,expected", [
    ("evil.execute-api.us-east-1.amazonaws.com", "evil.execute-api.us-east-1.amazonaws.com"),
    ("x.blob.core.windows.net", "x.blob.core.windows.net"),
    ("a.b.fly.dev", "a.b.fly.dev"),
    ("myapp.github.io", "myapp.github.io"),
    ("www.jan.ai", "jan.ai"), ("api.foo.co.uk", "foo.co.uk"), ("localhost", "localhost"), ("10.1.2.3", "10.1.2.3"),
])
def test_fm11_registrable_domain(host, expected):
    assert util.registrable_domain(host) == expected


def test_fm11_a_tracker_on_the_same_cloud_is_not_first_party():
    m = _m(first_party_domains=["myapp.s3.amazonaws.com"])
    flows = [{"capture_phase": "capture_idle", "host": h, "kind": "http", "method": "GET", "path": "/", "ts": 1.0, "req_bytes": 1, "payload_keys": [], "id_hashes": []}
             for h in ("myapp.s3.amazonaws.com", "tracker.execute-api.us-east-1.amazonaws.com")]
    labels, _ = classify_flows(flows, m, load_signatures(), Blocklist(), None, lambda *a: None)
    by = {x["host"]: x["features"]["first_party"] for x in labels}
    assert by == {"myapp.s3.amazonaws.com": True, "tracker.execute-api.us-east-1.amazonaws.com": False}


def test_fm11_shared_cloud_domain_in_manifest_warns():
    assert any("shared cloud" in w for w in _m(first_party_domains=["amazonaws.com"]).warnings)


# ---------------------------------------------------------------- FM33: domains typed by humans
def test_fm33_domain_entries_are_normalised_or_rejected():
    m = _m(first_party_domains=["https://Jan.AI/path", "*.foo.com", "bar.com:8443", "jan.ai"], allowed_domains=[".cdn.x.org"])
    assert m.first_party_domains == ["jan.ai", "foo.com", "bar.com"] and m.allowed_domains == ["cdn.x.org"]
    for bad in ([None], [42], ["not a domain"], [""]):
        with pytest.raises(ManifestError, match="not a valid domain"):
            _m(first_party_domains=bad)


def test_fm33_idna_hosts_are_compared_in_punycode():
    assert util.normalize_host("M\u00fcnchen.DE.") == "xn--mnchen-3ya.de"
    assert util.domain_matches("api.m\u00fcnchen.de", "xn--mnchen-3ya.de")


# ---------------------------------------------------------------- FM32: numeric sanity
@pytest.mark.parametrize("section,key,val", [
    ("capture", "idle_minutes", float("inf")), ("capture", "use_minutes", float("nan")), ("capture", "heartbeat_seconds", 0),
    ("capture", "max_flows", -5), ("capture", "min_free_disk_mb", -1), ("capture", "payload_sample_bytes", 10**9),
    ("static", "workers", 0), ("static", "workers", 500), ("static", "chunk_mb", 0), ("static", "max_file_mb", 0),
    ("classify", "dns_timeout", 0), ("classify", "dns_timeout", 999), ("classify", "max_dns_lookups", -1),
])
def test_fm32_absurd_numbers_are_rejected(section, key, val):
    with pytest.raises(ManifestError, match=key):
        _m(**{section: {key: val}})


def test_fm32_yaml_dot_inf_is_rejected_from_a_real_file(tmp_path):
    p = tmp_path / "m.yaml"
    p.write_text("app: {name: X}\ncapture: {idle_minutes: .inf}\n", encoding="utf-8")
    with pytest.raises(ManifestError, match="finite"):
        load_manifest(p)


def test_fm32_document_urls_must_be_http_and_repo_hosts_cannot_be_options():
    with pytest.raises(ManifestError, match="http"):
        _m(sources={"documents": [{"type": "url", "location": "file:///etc/passwd", "role": "readme"}]})
    for url in ("ssh://-oProxyCommand=evil/x", "git@-oProxyCommand=evil:x/y", "https://-evil.com/x"):
        with pytest.raises(ManifestError, match="repo_url"):
            _m(sources={"repo_url": url})
    assert _m(sources={"repo_url": "git@github.com:a/b.git"}).sources.repo_url


def test_fm20_webview2_apps_get_a_warning_about_the_child_process():
    m = _m(app={"name": "X", "exe_name": "x.exe", "stack": "Tauri"}, capture={"mode": "local"})
    assert any("msedgewebview2" in w for w in m.warnings)
    m2 = _m(app={"name": "X", "exe_name": "x.exe,msedgewebview2.exe", "stack": "Tauri"}, capture={"mode": "local"})
    assert not any("msedgewebview2" in w for w in m2.warnings)


# ---------------------------------------------------------------- FM34: template quoting
@pytest.mark.parametrize("name", ['My "Notes" App', "C:\\Users\\x {y}", "Caf\u00e9 \u65e5\u672c\u8a9e", "a: b # c", "x'y", "line\\nbreak"])
def test_fm34_generated_manifests_always_roundtrip(name):
    m = parse_manifest(yaml.safe_load(render_template(name, homepage='https://x.org/?a="b"', repo_url="https://github.com/a/b", first_party=["x.org"])))
    assert m.app.name == name and m.first_party_domains == ["x.org"]


def test_fm34_every_catalogue_candidate_produces_a_valid_manifest():
    for a in list_candidates():
        m = parse_manifest(yaml.safe_load(manifest_text_for(a["slug"])))
        assert m.app.slug == a["slug"]


# ---------------------------------------------------------------- FM35: encodings
def test_fm35_utf16_and_bom_manifests_load(tmp_path):
    (tmp_path / "u16.yaml").write_bytes("app:\n  name: Caf\u00e9\n".encode("utf-16"))  # what PowerShell '>' writes
    (tmp_path / "bom.yaml").write_bytes(b"\xef\xbb\xbf" + "app:\n  name: Caf\u00e9\n".encode())
    assert load_manifest(tmp_path / "u16.yaml").app.name == "Caf\u00e9" == load_manifest(tmp_path / "bom.yaml").app.name


def test_fm35_undecodable_manifest_is_a_clean_error(tmp_path):
    (tmp_path / "bad.yaml").write_bytes(b"app:\n  name: \xff\xfe\xfa\n")
    with pytest.raises(ManifestError, match="UTF-8"):
        load_manifest(tmp_path / "bad.yaml")


# ---------------------------------------------------------------- FM36: slugs
@pytest.mark.parametrize("name,expected", [("Con", "con-app"), ("NUL", "nul-app"), ("com1", "com1-app"), ("Caf\u00e9 Notes", "cafe-notes"), (" My App! v2 ", "my-app-v2"), ("///", "app")])
def test_fm36_slugs_are_filesystem_safe(name, expected):
    assert util.slugify(name) == expected


def test_fm36_non_latin_names_do_not_collide_and_length_is_capped():
    a, b = util.slugify("\u65e5\u672c\u8a9e\u30ce\u30fc\u30c8"), util.slugify("\u4e2d\u6587\u7b14\u8bb0")
    assert a != b and a.startswith("app-") and len(util.slugify("A" * 400)) <= util.SLUG_MAX


def test_is_safe_name():
    assert util.is_safe_name("20260101-000000") and util.is_safe_name("my-app")
    for bad in ("", "..", ".", "../x", "a/b", "a\\b", "c:x", " x", "x\x00"):
        assert not util.is_safe_name(bad)


# ---------------------------------------------------------------- FM12: redaction (util and addon must agree)
SAMPLES = [
    "C:\\\\Users\\\\MarcoRossi\\\\Documents\\\\a.txt and C:\\Users\\Anna\\x", "/home/marco/.config/x /Users/anna/Library",
    "ip 192.168.1.23 and 10.0.0.1 but version 10.0.19045.1 and 1.2.3", "mac 00:1A:2B:3C:4D:5E",
    "AKIAIOSFODNN7EXAMPLE sk-abcdefghijklmnopqrstuv ghp_abcdefghijklmnopqrstuvwxyz0123", "Authorization: Bearer abcdefgh12345678",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP", "https://user:hunter2@host.example/x", "a@b.com 3f2b8c1e-1111-2222-3333-444455556666 123456789012",
]


@pytest.mark.parametrize("text", SAMPLES)
def test_fm12_addon_and_core_redaction_are_identical(text):
    assert addon.redact(text) == util.redact_text(text)


def test_fm12_redaction_masks_identifiers_but_keeps_useful_signal():
    out = util.redact_text(" | ".join(SAMPLES))
    for secret in ("MarcoRossi", "Anna", "marco", "192.168.1.23", "00:1A:2B", "AKIAIOSFODNN7EXAMPLE", "hunter2", "a@b.com", "abcdefgh12345678", "123456789012"):
        assert secret not in out
    assert "10.0.19045.1" in out and "1.2.3" in out  # version strings survive


def test_fm12_path_and_key_names_are_redacted_in_flow_records():
    rec = addon.build_flow_record(
        method="POST", scheme="https", host="x.com", port=443, path_qs="/v1/users/marco.rossi@example.com/track/123456789012?tok=abc",
        req_headers={"content-type": "application/json", "user-agent": "App/1 (C:\\Users\\Marco\\app.exe)"},
        body=json.dumps({"3f2b8c1e-1111-2222-3333-444455556666": 1, "a@b.com": 2, "event": "x"}).encode(), status=200, resp_bytes=1, ts=1.0)
    blob = json.dumps(rec)
    for secret in ("marco.rossi@example.com", "123456789012", "3f2b8c1e-1111", "a@b.com", "Marco\\\\"):
        assert secret not in blob
    assert rec["path"] == "/v1/users/<email>/track/<num>" and "event" in rec["payload_keys"]


# ---------------------------------------------------------------- FM37: signature file validation
@pytest.mark.parametrize("bad,match", [
    ({"vendors": [{"id": "x", "domains": "foo.com"}]}, "list of non-empty strings"),
    ({"vendors": [{"id": "x", "domains": ["not a domain"]}]}, "not a valid domain"),
    ({"vendors": [{"id": "x", "packages": {"rust": ["a"]}}]}, "unknown ecosystem"),
    ({"vendors": [{"id": "x", "packages": {"npm": "a"}}]}, "list of strings"),
    ({"vendors": [{"id": "bad id!"}]}, "'id'"), ({"vendors": [{"id": "x", "name": 5}]}, "text"),
])
def test_fm37_malformed_vendor_definitions_are_rejected_clearly(bad, match):
    with pytest.raises(ClaimCheckError, match=match):
        _parse_vendor_file(bad, "t")


def test_fm37_extra_signature_files_bad_yaml_and_overrides(tmp_path):
    (tmp_path / "bad.yaml").write_text("vendors: [\n", encoding="utf-8")
    with pytest.raises(ClaimCheckError, match="not valid YAML"):
        load_signatures([str(tmp_path / "bad.yaml")])
    (tmp_path / "ok.yaml").write_text("vendors:\n  - {id: sentry, domains: [example-sentry.io]}\n", encoding="utf-8")
    assert load_signatures([str(tmp_path / "ok.yaml")]).overridden == ["sentry"]


def test_new_vendors_are_present():
    s = load_signatures()
    assert s.match_domain("www.clarity.ms").category == "session_replay" and s.match_package("npm", "@honeycombio/x").id == "honeycomb"


# ---------------------------------------------------------------- FM38: blocklists
def test_fm38_disconnect_parsing_ignores_non_domain_values(tmp_path):
    p = tmp_path / "services.json"
    p.write_text(json.dumps({"categories": {"Analytics": [{"Acme": {"http://acme.com/": ["acme-track.com", 5, None], "dnt": "eff", "performance": "true"}}, "junk", 5]}}))
    bl = Blocklist()
    assert bl.add_file(p) == 1 and set(bl.domains) == {"acme-track.com"}
    assert bl.provenance[0]["sha256"] and bl.provenance[0]["domains"] == 1


def test_fm38_broken_or_alien_json_lists_are_skipped_not_fatal(tmp_path):
    (tmp_path / "a.json").write_text('{"categories": [1, 2]}')
    (tmp_path / "b.json").write_text("{not json")
    logs = []
    bl = load_blocklists([str(tmp_path / "a.json"), str(tmp_path / "b.json")], include_default_dir=False, log=logs.append)
    assert len(bl) == 0 and sum("unreadable" in m for m in logs) == 2


def test_fm38_hosts_format_takes_every_name_and_ignores_ips(tmp_path):
    (tmp_path / "hosts.txt").write_text("127.0.0.1 localhost\n0.0.0.0 ads.a.com trk.b.com\n||x.y.org^\n0.0.0.0 0.0.0.0\nplain.example\n")
    bl = Blocklist()
    bl.add_file(tmp_path / "hosts.txt")
    assert set(bl.domains) == {"ads.a.com", "trk.b.com", "x.y.org", "plain.example"}


def test_fm38_download_is_atomic_and_partial_files_are_ignored(tmp_path, monkeypatch):
    import claimcheck.classify.blocklists as B

    class R:
        text = '{"categories": {}}'

        def raise_for_status(self):
            pass

    monkeypatch.setattr(B.requests, "get", lambda *a, **k: R())
    out = fetch_default_lists(tmp_path)[0]
    assert out.exists() and not list(tmp_path.glob("*.part"))
    (tmp_path / "half.json.part").write_text("{trunc")
    monkeypatch.setattr(B, "DEFAULT_LISTS_DIR", tmp_path)
    assert all(not str(p).endswith(".part") for p in [x for x in tmp_path.glob("*") if x.suffix not in (".part", ".tmp")])


# ---------------------------------------------------------------- FM41: domains only match on a word boundary
def test_fm41_domain_needles_need_a_left_boundary_but_prefixes_still_count():
    for utf16 in (False, True):
        m = ContentMatcher([("countly", "count.ly"), ("sentry", "sentry.io")], utf16)
        enc = (lambda t: t.encode("utf-16-le")) if utf16 else (lambda t: t.encode())
        assert m.scan_chunk(enc("visit account.ly or discount.ly")) == {}
        assert set(m.scan_chunk(enc("https://count.ly/i o0.ingest.sentry.io"))) == {"countly", "sentry"}


# ---------------------------------------------------------------- FM43: DNS circuit breaker
def _dns_flows(n):
    return [{"capture_phase": "capture_idle", "host": f"h{i}.testapp.test", "kind": "http", "method": "GET", "path": "/", "ts": 1.0,
             "req_bytes": 1, "payload_keys": [], "id_hashes": []} for i in range(n)]


def test_fm43_offline_resolver_stops_after_five_failures_and_says_so():
    calls, logs, notes = [], [], {}
    m = _m(first_party_domains=["testapp.test"])

    def resolver(h):
        calls.append(h)
        return [], "timeout"

    classify_flows(_dns_flows(20), m, load_signatures(), Blocklist(), resolver, lambda lvl, msg: logs.append((lvl, msg)), notes)
    assert len(calls) == 5 and notes["dns_unavailable"] is True and len(notes["dns_skipped_hosts"]) == 15
    assert any(lvl == "WARN" and "NOT performed" in msg for lvl, msg in logs)


def test_fm43_lookup_limit_is_reported_and_healthy_dns_is_untouched():
    notes = {}
    m = _m(first_party_domains=["testapp.test"], classify={"max_dns_lookups": 3})
    calls = []
    classify_flows(_dns_flows(8), m, load_signatures(), Blocklist(), lambda h: (calls.append(h) or ([], "")), lambda *a: None, notes)
    assert len(calls) == 3 and notes["dns_limit_reached"] is True and not notes["dns_unavailable"]


def test_fm43_zero_size_posts_are_not_flagged_as_uniform_event_batches():
    flows = [{"capture_phase": "capture_idle", "host": "x.other.test", "kind": "http", "method": "POST", "path": "/p", "ts": 100.0 * i,
              "req_bytes": 0, "payload_keys": [], "id_hashes": []} for i in range(1, 6)]
    labels, _ = classify_flows(flows, _m(), load_signatures(), Blocklist(), None, lambda *a: None)
    assert not any("small POSTs" in r for r in labels[0]["reasons"])
