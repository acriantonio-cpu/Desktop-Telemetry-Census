from __future__ import annotations

import pytest

from claimcheck.claims import (
    LoadedDoc, extract_claims, extract_disclosed_vendors, html_to_text, load_documents, markdown_to_text, split_sentences,
)
from claimcheck.manifest import parse_manifest
from claimcheck.signatures import load_signatures

SIGS = load_signatures()


def _kinds(text, role="readme"):
    return {c["kind"] for c in extract_claims([LoadedDoc(role, "x", text)])}


@pytest.mark.parametrize("text,kind", [
    ("We have no telemetry.", "no_telemetry"), ("The app does not collect any analytics.", "no_telemetry"),
    ("A telemetry-free editor.", "no_telemetry"), ("Nessuna telemetria, mai.", "no_telemetry"),
    ("A local-first notes app.", "local_first"), ("It runs 100% offline.", "local_first"),
    ("Your notes never leave your device.", "local_first"), ("Works offline.", "local_first"),
    ("A privacy-friendly browser.", "privacy_friendly"), ("We respect your privacy.", "privacy_friendly"),
    ("Fully open-source software.", "open_source"), ("Licensed under the MIT license.", "open_source"),
    ("We never sell your data.", "no_third_party_sharing"), ("No third parties get access.", "no_third_party_sharing"),
])
def test_claim_patterns_match(text, kind):
    assert kind in _kinds(text)


@pytest.mark.parametrize("text", [
    "We collect anonymous usage data to improve the app.", "Telemetry is enabled by default.",
    "Click here to download.", "The weather is nice today.",
])
def test_non_claims_do_not_match_no_telemetry(text):
    assert "no_telemetry" not in _kinds(text)


def test_qualifiers_lower_confidence_and_are_recorded():
    plain = extract_claims([LoadedDoc("readme", "x", "We have no telemetry.")])[0]
    qual = extract_claims([LoadedDoc("readme", "x", "We have no telemetry unless you opt in.")])[0]
    assert qual["confidence"] < plain["confidence"]
    assert "unless" in qual["detail"]["qualifiers"] and "opt in" in " ".join(qual["detail"]["qualifiers"]).replace("-", " ")


def test_dedup_and_cap_per_kind():
    text = "\n".join(f"Fully open-source variant {i}." for i in range(20)) + "\nFully open-source variant 1."
    cl = extract_claims([LoadedDoc("readme", "x", text)])
    assert len([c for c in cl if c["kind"] == "open_source"]) <= 6


def test_html_and_markdown_cleaning():
    h = "<html><head><title>t</title><script>var a='no telemetry';</script></head><body><p>We are <b>local-first</b>.</p><style>x{}</style></body></html>"
    txt = html_to_text(h)
    assert "local-first" in txt and "var a" not in txt and "x{}" not in txt
    md = "# Title\n[link](http://x) `code` ![img](a.png)\n```\nno telemetry in code block\n```\nreal text"
    out = markdown_to_text(md)
    assert "http" not in out and "code block" not in out and "real text" in out
    assert html_to_text("<div><p>unclosed") != ""  # malformed HTML tolerated


def test_split_sentences_filters_short_and_truncates():
    assert split_sentences("Hi.\n\n- A proper sentence here.\n* Another proper one!") == ["A proper sentence here.", "Another proper one!"]
    # long legal sentences are kept whole for matching (only absurd blobs are windowed); display snippets are capped elsewhere
    assert split_sentences("y " * 400 + ".")[0].startswith("y y")
    assert all(len(s) <= 3000 for s in split_sentences("x" * 20000 + "."))


def test_disclosed_vendors_only_from_privacy_policy():
    policy = LoadedDoc("privacy_policy", "p", "We use Sentry and Google Analytics. Data goes to eu.i.posthog.com too.")
    readme = LoadedDoc("readme", "r", "We use Mixpanel.")
    got = {d["sdk_id"] for d in extract_disclosed_vendors([policy, readme], SIGS)}
    assert got - {"__generic_telemetry__"} == {"sentry", "google_analytics", "posthog"}  # generic admission is added on top
    assert extract_disclosed_vendors([LoadedDoc("privacy_policy", "p", "Nothing is sent, ever.")], SIGS) == []
    assert extract_disclosed_vendors([LoadedDoc("privacy_policy", "p", "We love sentryless code.")], SIGS) == []  # word boundary


def test_load_documents_from_files_urls_and_failures(tmp_path):
    (tmp_path / "policy.html").write_text("<p>We never sell your data.</p>", encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "README.md").write_text("Local-first app.", encoding="utf-8")
    m = parse_manifest({"app": {"name": "A", "exe_name": "a"}, "sources": {"repo_path": str(repo), "documents": [
        {"type": "file", "location": str(tmp_path / "policy.html"), "role": "privacy_policy"},
        {"type": "url", "location": "https://ok.test/", "role": "homepage"},
        {"type": "url", "location": "https://down.test/", "role": "other"},
        {"type": "file", "location": str(tmp_path / "missing.md"), "role": "other"}]}})
    logs = []

    def fetch(url):
        if "down" in url:
            raise OSError("connection refused")
        return "text/html", "<p>Runs 100% offline.</p>"

    docs = load_documents(m, tmp_path / "cache", lambda lvl, msg: logs.append((lvl, msg)), fetch)
    by_ref = {d.ref: d for d in docs}
    assert len(docs) == 5  # 4 configured + auto README
    assert "never sell" in by_ref[str(tmp_path / "policy.html")].text
    assert by_ref["https://down.test/"].error and by_ref[str(tmp_path / "missing.md")].error
    assert any(d.role == "readme" and "Local-first" in d.text for d in docs)
    assert sum(1 for lvl, m in logs if lvl == "WARN" and m.startswith("could not load")) == 2
    assert len(list((tmp_path / "cache").glob("*.txt"))) == 3
