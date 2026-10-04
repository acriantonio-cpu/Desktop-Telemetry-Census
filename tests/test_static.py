from __future__ import annotations

import json
import zipfile

import pytest

from claimcheck.manifest import StaticCfg
from claimcheck.signatures import SignatureSet, Vendor, load_signatures
from claimcheck.static import asar
from claimcheck.static.repo_deps import parse_repo_dependencies
from claimcheck.static.scanner import scan_chunks, scan_install, scan_repo
from helpers import build_asar

SIGS = load_signatures()


def _ids(res, kind=None):
    return {(e["sdk_id"], e["kind"]) for e in res.evidence if kind is None or e["kind"] == kind}


# ------------------------------------------------------------------ signatures
def test_signature_lookups():
    assert SIGS.match_domain("o1.ingest.sentry.io").id == "sentry"
    assert SIGS.match_domain("eu.i.posthog.com").id == "posthog"
    assert SIGS.match_domain("example.com") is None
    assert SIGS.match_package("npm", "@sentry/node").id == "sentry"
    assert SIGS.match_package("pypi", "Sentry_SDK").id == "sentry"  # name normalisation
    assert SIGS.match_package("npm", "left-pad") is None
    assert SIGS.match_filename("Microsoft.ApplicationInsights.dll").id == "appinsights"


def test_signature_payload_roundtrip_and_extra_file(tmp_path):
    again = SignatureSet.from_payload(SIGS.to_payload())
    assert again.digest() == SIGS.digest() and set(again.vendors) == set(SIGS.vendors)
    extra = tmp_path / "x.yaml"
    extra.write_text("vendors:\n  - id: mytel\n    name: My Telemetry\n    domains: [telemetry.mycorp.io]\n", encoding="utf-8")
    merged = load_signatures([str(extra)])
    assert merged.match_domain("a.telemetry.mycorp.io").id == "mytel"


def test_bad_signature_files_are_rejected(tmp_path):
    from claimcheck.errors import ClaimCheckError

    bad = tmp_path / "bad.yaml"
    bad.write_text("vendors:\n  - {id: a, colour: red}\n", encoding="utf-8")
    with pytest.raises(ClaimCheckError, match="unknown keys"):
        load_signatures([str(bad)])
    with pytest.raises(ClaimCheckError):
        load_signatures([str(tmp_path / "missing.yaml")])


# ------------------------------------------------------------------ chunk scanning
def test_match_spanning_chunk_boundary_is_counted_once():
    m = SIGS.matcher(False)
    data = b"A" * 99 + b" api.mixpanel.com " + b"B" * 100  # domains must sit on a word boundary
    for cut in (105, 110, 115):  # split inside the needle
        res = scan_chunks([data[:cut], data[cut:]], m)
        assert res["mixpanel"]["count"] >= 1
        assert res["mixpanel"]["patterns"] >= {"api.mixpanel.com"}
    whole = scan_chunks([data], m)
    split = scan_chunks([data[:110], data[110:]], m)
    assert whole["mixpanel"]["count"] == split["mixpanel"]["count"]


def test_utf16_strings_detected_only_when_enabled():
    needle = "dc.services.visualstudio.com".encode("utf-16-le")
    assert "appinsights" in scan_chunks([b"\0\0" + needle], SIGS.matcher(True))
    assert "appinsights" not in scan_chunks([b"\0\0" + needle], SIGS.matcher(False))


# ------------------------------------------------------------------ asar
def test_asar_roundtrip_and_bounds(tmp_path):
    p = tmp_path / "app.asar"
    p.write_bytes(build_asar({"a/b.js": b"hello", "c.txt": b"world!"}))
    entries = {e.path: e for e in asar.iter_entries(p)}
    assert set(entries) == {"a/b.js", "c.txt"}
    assert b"".join(asar.read_entry(p, entries["c.txt"], 4)) == b"world!"


def test_asar_rejects_garbage_and_skips_out_of_bounds_entries(tmp_path):
    bad = tmp_path / "bad.asar"
    bad.write_bytes(b"not an archive at all, definitely")
    with pytest.raises(asar.AsarError):
        list(asar.iter_entries(bad))
    tiny = tmp_path / "tiny.asar"
    tiny.write_bytes(b"1234")
    with pytest.raises(asar.AsarError):
        asar.read_header(tiny)
    blob = bytearray(build_asar({"x.js": b"data"}))
    p = tmp_path / "trunc.asar"
    p.write_bytes(bytes(blob[:-2]))  # data truncated: entry now points outside the file
    assert list(asar.iter_entries(p)) == []


# ------------------------------------------------------------------ install scan
def test_scan_install_finds_packages_filenames_strings_in_dir_asar_and_zip(tmp_path):
    root = tmp_path / "app"
    (root / "resources").mkdir(parents=True)
    (root / "node_modules/@sentry/node").mkdir(parents=True)
    (root / "node_modules/@sentry/node/index.js").write_text("x")
    (root / "Sentry.Core.dll").write_bytes(b"MZ")
    (root / "main.js").write_text("fetch('https://api.mixpanel.com/track')")
    (root / "resources/app.asar").write_bytes(build_asar({
        "src/x.js": b"posthog.capture('e'); // https://eu.i.posthog.com/capture/",
        "node_modules/@bugsnag/js/package.json": b"{}",
    }))
    with zipfile.ZipFile(root / "plugin.zip", "w") as z:
        z.writestr("lib/a.js", "https://o1.ingest.sentry.io/api/1/envelope/")
        z.writestr("node_modules/rollbar/package.json", "{}")
    res = scan_install(root, SIGS, StaticCfg())
    got = _ids(res)
    assert ("sentry", "sdk_package") in got and ("sentry", "sdk_filename") in got
    assert ("mixpanel", "sdk_string") in got and ("posthog", "sdk_string") in got
    assert ("bugsnag", "sdk_package") in got and ("rollbar", "sdk_package") in got
    assert any("app.asar!/" in e["location"] for e in res.evidence)
    assert res.coverage["files_scanned"] >= 4 and not res.coverage["errors"]


def test_scan_respects_skip_lists_size_and_budget(tmp_path):
    root = tmp_path / "app"
    root.mkdir()
    (root / "image.png").write_bytes(b"api.mixpanel.com")  # skipped by glob
    (root / "electron.exe").write_bytes(b"api.mixpanel.com")  # runtime file
    (root / "huge.bin").write_bytes(b"a" * (3 * 1024 * 1024) + b"api.mixpanel.com")  # bigger than max_file_mb=1
    (root / "ok.js").write_text("api.amplitude.com")
    res = scan_install(root, SIGS, StaticCfg(max_file_mb=1, max_total_mb=1))
    assert _ids(res, "sdk_string") == {("amplitude", "sdk_string")}
    cov = res.coverage
    assert cov["skipped_glob"] == 1 and cov["skipped_runtime"] == 1 and cov["skipped_size"] == 1
    res2 = scan_install(root, SIGS, StaticCfg(skip_runtime_files=False, max_file_mb=10))
    assert ("mixpanel", "sdk_string") in _ids(res2)  # runtime skip can be disabled


def test_total_budget_is_enforced(tmp_path):
    root = tmp_path / "app"
    root.mkdir()
    for i in range(5):
        (root / f"f{i}.bin").write_bytes(b"x" * (600 * 1024))
    res = scan_install(root, SIGS, StaticCfg(max_total_mb=1))
    assert res.coverage["skipped_budget"] >= 3 and res.coverage["bytes_scanned"] <= 1024 * 1024


def test_parallel_workers_give_same_evidence_as_sequential(tmp_path):
    root = tmp_path / "app"
    root.mkdir()
    for i in range(6):
        (root / f"m{i}.js").write_text("https://api.mixpanel.com https://o1.ingest.sentry.io")
    seq = scan_install(root, SIGS, StaticCfg(workers=1))
    par = scan_install(root, SIGS, StaticCfg(workers=2))
    key = lambda r: sorted((e["sdk_id"], e["kind"], e["location"]) for e in r.evidence)  # noqa: E731
    assert key(seq) == key(par) and par.coverage["workers"] == 2


def test_corrupt_archives_are_reported_not_fatal(tmp_path):
    root = tmp_path / "app"
    root.mkdir()
    (root / "broken.asar").write_bytes(b"garbage garbage garbage")
    (root / "ok.js").write_text("api.mixpanel.com")
    res = scan_install(root, SIGS, StaticCfg())
    assert ("mixpanel", "sdk_string") in _ids(res)
    assert any("broken.asar" in e for e in res.coverage["errors"])


def test_single_file_target_and_symlinks(tmp_path):
    f = tmp_path / "tool.exe"
    f.write_bytes(b"xx" + "api.mixpanel.com".encode("utf-16-le"))
    assert ("mixpanel", "sdk_string") in _ids(scan_install(f, SIGS, StaticCfg()))
    root = tmp_path / "d"
    root.mkdir()
    (root / "real.js").write_text("api.mixpanel.com")
    try:
        (root / "link.js").symlink_to(root / "real.js")
    except OSError:
        pytest.skip("symlinks unavailable")
    res = scan_install(root, SIGS, StaticCfg())
    assert res.coverage["files_seen"] == 1  # symlinks are not followed


# ------------------------------------------------------------------ repo dependencies
def test_repo_dependency_parsers(tmp_path):
    r = tmp_path / "repo"
    (r / "sub").mkdir(parents=True)
    (r / "package.json").write_text(json.dumps({"dependencies": {"electron": "1", "@sentry/electron": "^4"}, "devDependencies": {"posthog-js": "1"}}))
    (r / "package-lock.json").write_text(json.dumps({"packages": {"": {}, "node_modules/a/node_modules/rollbar": {}, "node_modules/lodash": {}}}))
    (r / "yarn.lock").write_text('"@bugsnag/js@^7.0.0":\n  version "7"\nleft-pad@^1.0.0:\n  version "1"\n')
    (r / "requirements.txt").write_text("requests>=2\nsentry-sdk[flask]==1.0  # crash\n-r other.txt\n")
    (r / "pyproject.toml").write_text('[project]\ndependencies = ["posthog>=3"]\n[project.optional-dependencies]\nx = ["mixpanel"]\n[tool.poetry.dependencies]\npython = "^3.11"\nampli = "1"\n')
    (r / "Cargo.toml").write_text('[dependencies]\nsentry = "0.3"\nrenamed = { package = "posthog-rs", version = "1" }\n')
    (r / "Cargo.lock").write_text('[[package]]\nname = "opentelemetry-otlp"\nversion = "0.1"\n')
    (r / "go.mod").write_text("module x\nrequire (\n\tgithub.com/getsentry/sentry-go v0.20.0\n)\n")
    (r / "sub/App.csproj").write_text('<Project><ItemGroup><PackageReference Include="Sentry.Serilog" Version="1"/></ItemGroup></Project>')
    (r / "node_modules").mkdir()
    (r / "node_modules/package.json").write_text(json.dumps({"dependencies": {"should-be-ignored": "1"}}))
    deps, stats = parse_repo_dependencies(r)
    names = {(d.ecosystem, d.name) for d in deps}
    assert {("npm", "@sentry/electron"), ("npm", "posthog-js"), ("npm", "rollbar"), ("npm", "@bugsnag/js"),
            ("pypi", "sentry-sdk"), ("pypi", "posthog"), ("pypi", "mixpanel"), ("cargo", "sentry"), ("cargo", "posthog-rs"),
            ("cargo", "opentelemetry-otlp"), ("go", "github.com/getsentry/sentry-go"), ("nuget", "Sentry.Serilog")} <= names
    assert ("npm", "should-be-ignored") not in names and ("pypi", "python") not in names
    assert stats["manifests_parsed"] >= 8


def test_malformed_manifests_do_not_crash(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    (r / "package.json").write_text("{not json")
    (r / "pyproject.toml").write_text("[[[")
    (r / "Cargo.toml").write_text("= =")
    deps, stats = parse_repo_dependencies(r)
    assert deps == [] and stats["manifests_parsed"] == 3


def test_scan_repo_combines_dependencies_and_source_strings(tmp_path):
    r = tmp_path / "repo"
    (r / "src").mkdir(parents=True)
    (r / "package.json").write_text(json.dumps({"dependencies": {"posthog-node": "1"}}))
    (r / "src/a.ts").write_text("const url = 'https://o1.ingest.sentry.io/1'")
    (r / "README.md").write_text("api.mixpanel.com")  # .md is not scanned as source
    res = scan_repo(r, SIGS, StaticCfg())
    got = _ids(res)
    assert ("posthog", "sdk_dependency") in got and ("sentry", "sdk_string") in got and ("mixpanel", "sdk_string") not in got
    assert all(e["side"] == "repo" for e in res.evidence)


def test_vendor_dataclass_defaults():
    v = Vendor(id="x", name="X")
    assert v.domains == [] and v.category == "analytics"
