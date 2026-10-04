"""0.2.0 regression tests, part 1: verdict validity (docs/12-failure-modes.md: FM01-FM12)."""

from __future__ import annotations

import base64
import shutil
import subprocess
from pathlib import Path

import pytest

from claimcheck import pipeline
from claimcheck.claims import (
    GENERIC_DISCLOSURE, LoadedDoc, _decode_body, extract_claims, extract_disclosed_vendors, fold_typography, http_fetch,
    is_usable_policy,
)
from claimcheck.models import DONE, V_CONTRADICTED, V_INCONCLUSIVE, V_NOT_CONTRADICTED, V_WARNING, PhaseResult
from claimcheck.pipeline import is_stale, phase_claims, phase_classify, run_phase
from claimcheck.scoring.checks import Facts, build_facts, collect_quality, run_checks
from claimcheck.signatures import load_signatures
from test_pipeline_report import _import
from test_scoring import _by, _claim, _facts, _label

SIGS = load_signatures()
ALL_KINDS = ["no_telemetry", "no_third_party_sharing", "local_first", "privacy_friendly"]


def _label_opaque(host="pinned.example", cls="opaque_unknown"):
    x = _label(host=host, label=cls, sdk=None, cat=None, req=0)
    x["features"] = {"opaque_only": True}
    return x


# ---------------------------------------------------------------- FM01 / FM02: an empty or blind capture is not "clean"
@pytest.mark.parametrize("kind", ALL_KINDS)
def test_fm01_zero_record_capture_is_never_not_contradicted(kind):
    f = _facts([_claim(kind)], flows={"capture_idle": 0})
    assert _by(run_checks(f), kind)["verdict"] == V_INCONCLUSIVE
    # ...even when clean-looking labels survive from an EARLIER classification (e.g. that capture was later excluded):
    # the record-count gate itself must hold, not just the "not classified" gate.
    ok = _label(label="first_party", sdk=None, cat=None)
    ok["features"] = {"opaque_only": False}
    f2 = _facts([_claim(kind)], [ok], flows={"capture_idle": 0})
    assert _by(run_checks(f2), kind)["verdict"] == V_INCONCLUSIVE


def test_fm01_zero_record_capture_raises_a_data_quality_warning(ctx):
    a = ctx.store.begin_attempt("capture_idle")
    ctx.store.finish_attempt(a, DONE)
    f = build_facts(ctx.store)
    assert any("0 records" in w and "NOT evidence" in w for w in f.quality)
    assert any(v["check_id"] == "data_quality" for v in run_checks(f))


@pytest.mark.parametrize("kind", ALL_KINDS)
def test_fm02_traffic_that_was_never_inspected_is_inconclusive(kind):
    f = _facts([_claim(kind)], [_label_opaque()], flows={"capture_idle": 40})
    v = _by(run_checks(f), kind)
    assert v["verdict"] == V_INCONCLUSIVE and "inspect" in v["title"].lower()


def test_fm02_opaque_third_party_host_next_to_clean_traffic_is_a_warning():
    ok = _label(label="first_party", sdk=None, cat=None)
    ok["features"] = {"opaque_only": False}
    f = _facts([_claim("no_telemetry")], [ok, _label_opaque()], flows={"capture_idle": 40})
    assert _by(run_checks(f), "no_telemetry")["verdict"] == V_WARNING


def test_fm02_captured_but_unclassified_traffic_is_inconclusive():
    f = _facts([_claim("no_telemetry")], flows={"capture_idle": 40})
    assert _by(run_checks(f), "no_telemetry")["verdict"] == V_INCONCLUSIVE


def test_genuinely_clean_inspected_traffic_still_yields_not_contradicted():
    ok = _label(label="first_party", sdk=None, cat=None)
    ok["features"] = {"opaque_only": False}
    f = _facts([_claim("no_telemetry")], [ok], flows={"capture_idle": 40})
    assert _by(run_checks(f), "no_telemetry")["verdict"] == V_NOT_CONTRADICTED


# ---------------------------------------------------------------- FM09: incomplete static scan
def test_fm09_incomplete_static_scan_cannot_clear_open_source_claim():
    f = _facts([_claim("open_source")], sides={"binary", "repo"})
    f.static_coverage = {"binary": {"skipped_size": 3, "errors": [], "opaque_container_count": 0}}
    v = _by(run_checks(f), "open_source")
    assert v["verdict"] == V_INCONCLUSIVE and "NOT inspected" in v["explanation"]
    f.static_coverage = {"binary": {"skipped_size": 0, "errors": [], "opaque_container_count": 0}}
    assert _by(run_checks(f), "open_source")["verdict"] == V_NOT_CONTRADICTED


def test_fm09_opaque_containers_and_read_errors_count_as_gaps():
    f = Facts(static_coverage={"binary": {"opaque_container_count": 2, "errors": ["x: boom"]}})
    assert len(f.static_gaps()) == 2


# ---------------------------------------------------------------- FM07 / FM08: policy usability & generic disclosure
def test_fm07_unusable_policy_gives_inconclusive_not_mass_undisclosed():
    f = _facts([_claim("privacy_friendly")], [_label()], policy=False)
    f.policy_unusable = True
    v = _by(run_checks(f), "policy_disclosure")
    assert v["verdict"] == V_INCONCLUSIVE and "empty" in v["explanation"]


@pytest.mark.parametrize("text,usable", [
    ("We respect you. " * 60, True),
    ("Loading...", False),
    ("Just a moment... Checking your browser before accessing the site. " + "x " * 60, False),
    ("Short but real policy text that is under the limit.", False),
])
def test_fm07_policy_usability(text, usable):
    assert is_usable_policy(LoadedDoc("privacy_policy", "p", text)) is usable


def test_fm08_first_party_telemetry_with_general_admission_is_not_contradicted():
    lab = _label(host="telemetry.testapp.test", label="telemetry_first_party", sdk=None, cat=None)
    f = _facts([], [lab], policy=True, disclosed={GENERIC_DISCLOSURE})
    assert _by(run_checks(f), "policy_disclosure")["verdict"] == V_NOT_CONTRADICTED
    f2 = _facts([], [lab], policy=True, disclosed=set())
    assert _by(run_checks(f2), "policy_disclosure")["verdict"] == V_WARNING  # manual check, not an accusation
    f3 = _facts([], [_label()], policy=True, disclosed={GENERIC_DISCLOSURE})
    assert _by(run_checks(f3), "policy_disclosure")["verdict"] == V_CONTRADICTED  # a KNOWN vendor must still be named


# ---------------------------------------------------------------- FM03 / FM04 / FM05: claim extraction
def _kinds(text):
    return {c["kind"] for c in extract_claims([LoadedDoc("readme", "x", text)])}


@pytest.mark.parametrize("text,kind", [
    ("We don\u2019t collect telemetry.", "no_telemetry"),
    ("Our app is privacy\u2011friendly.", "privacy_friendly"),
    ("Fully local\u2010first, by design.", "local_first"),
    ("We never\u00a0sell\u00a0your data.", "no_third_party_sharing"),
    ("It is 100%\u200b offline.", "local_first"),
])
def test_fm03_typographic_characters_do_not_hide_claims(text, kind):
    assert kind in _kinds(text)


def test_fm03_fold_typography_maps_the_usual_suspects():
    assert fold_typography("don\u2019t \u201cx\u201d a\u2013b\u00a0c\u200bd") == "don't \"x\" a-b cd"


def test_fm03_utf8_pages_are_not_decoded_as_latin1():
    body = "We don\u2019t collect telemetry.".encode()
    assert "\u2019" in _decode_body(body, "text/html", "ISO-8859-1")  # no charset header -> UTF-8 first
    assert "\u00e9" in _decode_body("caf\u00e9".encode("latin-1"), "text/html; charset=iso-8859-1", None)


def test_fm04_claim_in_a_very_long_legal_sentence_is_found_and_snippet_is_bounded():
    text = "Lorem ipsum dolor sit amet, " * 40 + "and we never sell your data to anyone " + "consectetur adipiscing, " * 40 + "."
    claims = extract_claims([LoadedDoc("privacy_policy", "x", text)])
    assert [c["kind"] for c in claims] == ["no_third_party_sharing"]
    assert len(claims[0]["text"]) <= 410 and "never sell" in claims[0]["text"]


@pytest.mark.parametrize("text", [
    "This app is not open source.", "It is far from privacy-friendly.", "Unlike open source tools, this one is closed.",
    "Is it open source?", "Is Jan really privacy-friendly?",
])
def test_fm05_negated_and_interrogative_sentences_are_not_claims(text):
    assert not _kinds(text) & {"open_source", "privacy_friendly", "local_first"}


def test_fm05_the_negation_guard_does_not_kill_real_claims():
    assert "open_source" in _kinds("Unlike other apps, we are open source and proud of it.")


# ---------------------------------------------------------------- FM06: negated disclosure
def _disc(text):
    return {d["sdk_id"] for d in extract_disclosed_vendors([LoadedDoc("privacy_policy", "p", text)], SIGS)}


def test_fm06_negated_vendor_mentions_are_not_disclosures():
    assert _disc("We do not use Google Analytics, Mixpanel or Sentry.") == set()
    assert "google_analytics" not in _disc("We use Sentry for crashes and do not use Google Analytics.")
    assert "sentry" in _disc("We use Sentry for crashes and do not use Google Analytics.")
    assert "sentry" in _disc("We do not sell data but we use Sentry.")  # contrast: the negation ends at 'but'


def test_fm06_generic_admission_detected_and_its_negation_ignored():
    assert GENERIC_DISCLOSURE in _disc("We collect anonymous usage statistics to improve the app.")
    assert GENERIC_DISCLOSURE not in _disc("We do not collect any telemetry.")


# ---------------------------------------------------------------- FM44: document fetching
def test_fm44_non_http_urls_are_refused():
    with pytest.raises(ValueError, match="non-http"):
        http_fetch("file:///etc/passwd")


def test_fm07_short_documents_produce_warnings_and_a_claims_summary(ctx, tmp_path):
    from claimcheck.manifest import Document

    (tmp_path / "pol.md").write_text("Loading...", encoding="utf-8")
    (tmp_path / "rd.md").write_text("We have no telemetry. " * 10, encoding="utf-8")
    ctx.manifest.sources.documents = [Document("file", str(tmp_path / "pol.md"), "privacy_policy"), Document("file", str(tmp_path / "rd.md"), "readme")]
    res = run_phase(ctx, "claims", lambda a: phase_claims(ctx, a))
    assert res.summary["policy_docs_loaded"] == 0 and res.summary["policy_docs_unusable"] == 1
    assert res.summary["doc_warnings"]
    f = build_facts(ctx.store)
    assert f.policy_unusable and any("policy" in w for w in f.quality)


# ---------------------------------------------------------------- FM10: staleness on the SET of inputs
def test_fm10_exclude_and_include_make_downstream_results_stale(ctx):
    a1 = ctx.store.begin_attempt("capture_idle")
    ctx.store.finish_attempt(a1, DONE)
    a2 = ctx.store.begin_attempt("capture_idle")
    ctx.store.finish_attempt(a2, DONE)
    run_phase(ctx, "classify", lambda a: PhaseResult(DONE, {}))
    assert not is_stale(ctx, "classify")
    ctx.store.set_excluded(a2, True)  # the newest capture disappears: max(id) DROPS, the old heuristic saw nothing
    assert is_stale(ctx, "classify")
    ctx.store.set_excluded(a2, False)
    assert not is_stale(ctx, "classify")


def test_fm10_editing_the_manifest_makes_classify_and_score_stale(ctx):
    run_phase(ctx, "claims", lambda a: PhaseResult(DONE, {}))
    run_phase(ctx, "classify", lambda a: PhaseResult(DONE, {}))
    run_phase(ctx, "score", lambda a: PhaseResult(DONE, {}))
    assert not is_stale(ctx, "score")
    ctx.manifest_sha256 = "edited-after-the-fact"
    assert is_stale(ctx, "classify") and is_stale(ctx, "score") and not is_stale(ctx, "claims")


def test_fm10_score_warns_and_records_stale_classify(ctx):
    a1 = ctx.store.begin_attempt("capture_idle")
    ctx.store.finish_attempt(a1, DONE)
    run_phase(ctx, "classify", lambda a: PhaseResult(DONE, {}))
    ctx.store.set_excluded(a1, True)
    res = run_phase(ctx, "score", lambda a: pipeline.phase_score(ctx, a))
    checks = ctx.store.select("verdicts", ctx.store.effective_attempt_ids("score"))
    assert any(v["check_id"] == "data_quality" and "older than their inputs" in v["explanation"] for v in checks)
    assert res.status == DONE


# ---------------------------------------------------------------- classify provenance / DNS notes
def test_classify_records_blocklist_provenance_and_dns_notes(ctx, tmp_path):
    bl = tmp_path / "list.txt"
    bl.write_text("tracker.example\n", encoding="utf-8")
    ctx.manifest.classify.blocklists = [str(bl)]
    ctx.manifest.classify.resolve_cname = True
    _import(ctx, "capture_idle", ["api.testapp.test", "eu.i.posthog.com"])
    res = run_phase(ctx, "classify", lambda a: phase_classify(ctx, a, resolver=lambda h: ([], "timeout")))
    assert any(p["name"] == "list.txt" and len(p["sha256"]) == 64 for p in res.summary["blocklists"])
    assert "dns_unavailable" in res.summary and "dns_skipped" in res.summary


# ---------------------------------------------------------------- FM42: git clone hardening / provenance
def test_fm42_clone_never_prompts_and_never_leaves_a_partial_repo(ctx, monkeypatch):
    seen = {}

    def boom(cmd, **kw):
        seen.update(kw, cmd=cmd)
        raise subprocess.CalledProcessError(128, cmd, stderr="fatal: could not read Username")

    monkeypatch.setattr(pipeline, "resolve_command", lambda c: ["git"])
    monkeypatch.setattr(pipeline.subprocess, "run", boom)
    ctx.manifest.sources.repo_url = "https://github.com/private/repo"
    assert pipeline.ensure_repo(ctx) is None
    assert seen["env"]["GIT_TERMINAL_PROMPT"] == "0" and seen["stdin"] == subprocess.DEVNULL
    assert "protocol.ext.allow=never" in seen["cmd"]
    assert not list(ctx.run.artifacts_dir.glob("repo*"))


def test_fm42_incomplete_previous_clone_is_not_reused(ctx, monkeypatch):
    dest = ctx.run.artifacts_dir / "repo"
    dest.mkdir(parents=True)
    (dest / "half.txt").write_text("x")

    def fake_run(cmd, **kw):
        part = Path(cmd[-1])
        (part / ".git").mkdir(parents=True)

    monkeypatch.setattr(pipeline, "resolve_command", lambda c: ["git"])
    monkeypatch.setattr(pipeline.subprocess, "run", fake_run)
    ctx.manifest.sources.repo_url = "https://github.com/a/b"
    got = pipeline.ensure_repo(ctx)
    assert got == dest and (dest / ".git").is_dir() and not (dest / "half.txt").exists()
    assert list(ctx.run.artifacts_dir.glob("repo.incomplete*"))


@pytest.mark.skipif(not shutil.which("git"), reason="git not installed")
def test_fm10_repo_info_detects_a_checkout_that_is_not_the_installed_version(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t", "PATH": str(Path(shutil.which("git")).parent)}
    for cmd in (["init", "-q"], ["commit", "-q", "--allow-empty", "-m", "x"], ["tag", "v1.2.3"]):
        subprocess.run(["git", "-C", str(repo), *cmd], check=True, env=env, capture_output=True)  # noqa: S603, S607
    assert pipeline.repo_info(repo, "1.2.3")["version_match"] is True
    assert pipeline.repo_info(repo, "9.9.9")["version_match"] is False
    assert pipeline.repo_info(repo, "")["version_match"] is None


def test_fm10_version_mismatch_becomes_a_quality_warning(ctx):
    a = ctx.store.begin_attempt("static")
    ctx.store.finish_attempt(a, DONE, {"sides": ["binary", "repo"], "coverage": {}, "repo_info": {"describe": "v0.9", "commit": "abc", "version_match": False}})
    assert any("does not look like the installed version" in w for w in collect_quality(ctx.store))


def test_data_url_base64_helper_smoke():  # keeps the base64 import honest for the HAR tests in part 3
    assert base64.b64decode(base64.b64encode(b"x")) == b"x"
