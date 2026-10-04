from __future__ import annotations

import json

import pytest

from claimcheck.errors import PreconditionError
from claimcheck.pipeline import (
    is_stale, next_actions, phase_claims, phase_classify, phase_report, phase_score, phase_static, resume, run_phase, status_rows,
)
from claimcheck.report.render import build_report_data, render_html
from helpers import build_asar, jsonl_flow

XSS = "<script>alert(1)</script>"


def _prep(ctx, tmp_path, with_repo=True):
    inst = tmp_path / "install"
    (inst / "resources").mkdir(parents=True)
    (inst / "resources/app.asar").write_bytes(build_asar({"node_modules/@sentry/node/package.json": b"{}"}))
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text('{"dependencies":{"electron":"1"}}')
    readme = tmp_path / "README.md"
    readme.write_text(f"We have no telemetry. It is open-source. {XSS} is private by design.\n", encoding="utf-8")
    policy = tmp_path / "policy.md"
    policy.write_text("Privacy policy. We use Sentry for crash reports. " + "This document explains what data the application handles and why. " * 8, encoding="utf-8")
    m = ctx.manifest
    m.app.install_dir = str(inst)
    m.sources.repo_path = str(repo) if with_repo else ""
    from claimcheck.manifest import Document

    m.sources.documents = [Document("file", str(readme), "readme"), Document("file", str(policy), "privacy_policy")]


def _import(ctx, phase, hosts):
    att = ctx.store.begin_attempt(phase)
    path = ctx.run.raw_dir / f"{phase}_{att}.jsonl"
    lines = [json.dumps({"type": "meta"})] + [json.dumps(jsonl_flow(host=h, ts=1000 + i * 30.0)) for h in hosts for i in range(6)]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    rel = path.relative_to(ctx.run.path).as_posix()
    ctx.store.register_raw_file(att, phase, rel)
    from claimcheck.dynamic.ingest import ingest_all

    ingest_all(ctx.store, ctx.run, True, lambda *a: None, attempt_id=att)
    ctx.store.finish_attempt(att, "done")


def test_full_pipeline_produces_expected_verdicts(ctx, tmp_path):
    _prep(ctx, tmp_path)
    run_phase(ctx, "claims", lambda a: phase_claims(ctx, a))
    run_phase(ctx, "static", lambda a: phase_static(ctx, a))
    _import(ctx, "capture_idle", ["eu.i.posthog.com", "api.testapp.test"])
    run_phase(ctx, "classify", lambda a: phase_classify(ctx, a))
    res = run_phase(ctx, "score", lambda a: phase_score(ctx, a))
    verdicts = {v["check_id"]: v["verdict"] for v in ctx.store.select("verdicts", ctx.store.effective_attempt_ids("score"))}
    assert verdicts["no_telemetry"] == "CONTRADICTED" and verdicts["open_source"] == "CONTRADICTED"
    assert verdicts["policy_disclosure"] == "CONTRADICTED"  # posthog observed, policy names only sentry
    assert res.summary["counts"]["CONTRADICTED"] >= 3


def test_static_needs_something_to_scan_and_failure_is_recorded(ctx):
    with pytest.raises(PreconditionError):
        run_phase(ctx, "static", lambda a: phase_static(ctx, a))
    att = ctx.store.attempts("static")[0]
    assert att["status"] == "failed" and "nothing to scan" in att["note"]
    assert not ctx.store.effective_attempt_ids("static")


def test_claims_fails_clearly_when_no_document_loads(ctx, tmp_path):
    from claimcheck.manifest import Document

    ctx.manifest.sources.documents = [Document("file", str(tmp_path / "missing.md"), "readme")]
    with pytest.raises(PreconditionError, match="no document could be loaded"):
        run_phase(ctx, "claims", lambda a: phase_claims(ctx, a))


def test_classify_without_flows_is_a_soft_result(ctx):
    res = run_phase(ctx, "classify", lambda a: phase_classify(ctx, a))
    assert res.status == "done" and res.note == "no flows"


def test_stale_detection_and_resume_reruns_only_what_is_needed(ctx, tmp_path):
    _prep(ctx, tmp_path)
    _import(ctx, "capture_idle", ["eu.i.posthog.com"])
    ran = resume(ctx)
    assert ran == ["claims", "static", "classify", "score", "report"]
    assert resume(ctx) == []  # up to date: nothing runs
    _import(ctx, "capture_use", ["o1.ingest.sentry.io"])  # new data arrives
    assert is_stale(ctx, "classify") and is_stale(ctx, "score") and not is_stale(ctx, "claims")
    assert any("STALE" in r["status"] for r in status_rows(ctx) if r["phase"] == "classify")
    assert resume(ctx) == ["classify", "score", "report"]
    assert len(ctx.store.attempts("classify")) == 2  # history kept
    assert not is_stale(ctx, "report")


def test_excluding_an_attempt_changes_results_after_resume(ctx, tmp_path):
    _prep(ctx, tmp_path)
    _import(ctx, "capture_idle", ["eu.i.posthog.com"])
    resume(ctx)
    att = ctx.store.attempts("capture_idle")[0]["id"]
    ctx.store.set_excluded(att, True)
    labels_before = ctx.store.select("labels", ctx.store.effective_attempt_ids("classify"))
    assert labels_before  # the old classification is untouched (append-only)
    assert not ctx.store.effective_attempt_ids("capture_idle")


def test_next_actions_guides_the_user(ctx):
    tips = " ".join(next_actions(ctx))
    assert "claims" in tips and "static" in tips and "capture --phase idle" in tips


def test_report_escapes_untrusted_content_and_has_csp(ctx, tmp_path):
    _prep(ctx, tmp_path)
    run_phase(ctx, "claims", lambda a: phase_claims(ctx, a))
    run_phase(ctx, "static", lambda a: phase_static(ctx, a))
    _import(ctx, "capture_idle", [f"{XSS}.evil.test", "eu.i.posthog.com"])
    run_phase(ctx, "classify", lambda a: phase_classify(ctx, a))
    run_phase(ctx, "score", lambda a: phase_score(ctx, a))
    res = run_phase(ctx, "report", lambda a: phase_report(ctx, a))
    html = open(res.summary["html"], encoding="utf-8").read()
    assert "<script" not in html.lower().replace("script-src", "")  # no executable markup anywhere
    assert "&lt;script&gt;" in html
    assert "Content-Security-Policy" in html and "default-src 'none'" in html
    data = json.load(open(res.summary["json"], encoding="utf-8"))
    assert data["summary"] and data["limitations"] and data["app"]["name"] == "TestApp"


def test_reports_never_overwrite(ctx, tmp_path):
    _prep(ctx, tmp_path)
    run_phase(ctx, "claims", lambda a: phase_claims(ctx, a))
    a = run_phase(ctx, "report", lambda a: phase_report(ctx, a)).summary["html"]
    b = run_phase(ctx, "report", lambda a: phase_report(ctx, a)).summary["html"]
    assert a != b and len(list(ctx.run.reports_dir.glob("*.html"))) == 2


def test_render_handles_empty_run(ctx):
    html = render_html(build_report_data(ctx))
    assert "No verdicts yet" in html and "How to read this report" in html
