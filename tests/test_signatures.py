import pytest
import yaml

from claimcheck.errors import ClaimCheckError
from claimcheck.signatures import SignatureSet, load_signatures


@pytest.fixture(scope="module")
def sigs():
    return load_signatures()


def test_bundled_signatures_are_sane(sigs):
    assert len(sigs.vendors) >= 25
    for v in sigs.vendors.values():
        assert v.id and v.category in {"analytics", "crash_reporting", "session_replay", "apm", "ad_tracking", "os_telemetry"}


def test_domain_matching_uses_suffixes_not_substrings(sigs):
    assert sigs.match_domain("o123.ingest.sentry.io").id == "sentry"
    assert sigs.match_domain("EU.i.posthog.com").id == "posthog"
    assert sigs.match_domain("sentry.io.evil.com") is None
    assert sigs.match_domain("notposthog.com") is None


def test_package_matching_wildcards_and_normalisation(sigs):
    assert sigs.match_package("npm", "@sentry/electron").id == "sentry"
    assert sigs.match_package("pypi", "Sentry_SDK").id == "sentry"
    assert sigs.match_package("npm", "left-pad") is None
    assert sigs.match_package("nuget", "Microsoft.ApplicationInsights.WindowsServer").id == "appinsights"
    assert sigs.match_package("cargo", "sentry-tracing").id == "sentry"


def test_filename_matching(sigs):
    assert sigs.match_filename("Sentry.Core.dll").id == "sentry"
    assert sigs.match_filename("readme.txt") is None


def test_content_matcher_ascii_and_utf16_and_overlap(sigs):
    m = sigs.matcher(utf16=True)
    hits = m.scan_chunk(b"see api.mixpanel.com now")
    assert "mixpanel" in hits
    utf16 = "api.mixpanel.com".encode("utf-16-le")
    assert "mixpanel" in m.scan_chunk(b"xx" + utf16 + b"yy")
    assert "mixpanel" not in sigs.matcher(utf16=False).scan_chunk(b"xx" + utf16)
    # matches fully inside the already-seen tail must not be recounted
    data = b"api.mixpanel.com"
    assert m.scan_chunk(data, skip_before=len(data)) == {}


def test_payload_roundtrip_for_worker_processes(sigs):
    again = SignatureSet.from_payload(sigs.to_payload())
    assert again.digest() == sigs.digest() and again.match_domain("api.amplitude.com").id == "amplitude"


def test_extra_signature_files_merge_and_validate(tmp_path):
    extra = tmp_path / "extra.yaml"
    extra.write_text(yaml.safe_dump({"vendors": [{"id": "acme", "name": "Acme", "domains": ["telemetry.acme.io"]}]}))
    s = load_signatures([str(extra)])
    assert s.match_domain("x.telemetry.acme.io").id == "acme" and s.match_domain("o1.ingest.sentry.io")
    bad = tmp_path / "bad.yaml"
    bad.write_text(yaml.safe_dump({"vendors": [{"id": "x", "bogus": 1}]}))
    with pytest.raises(ClaimCheckError, match="unknown keys"):
        load_signatures([str(bad)])
    with pytest.raises(ClaimCheckError, match="not found"):
        load_signatures([str(tmp_path / "missing.yaml")])
