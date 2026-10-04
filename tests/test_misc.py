from __future__ import annotations

import pytest
import yaml
from typer.testing import CliRunner

from claimcheck.benchmark import evaluate, load_truth
from claimcheck.candidates import get_candidate, list_candidates, load_catalogue, manifest_text_for
from claimcheck.cli import app
from claimcheck.errors import ClaimCheckError
from claimcheck.manifest import parse_manifest
from claimcheck.resources import ResourceGuard, doctor_checks, recommend_static_workers, resolve_command


# ------------------------------------------------------------------ candidates
def test_catalogue_is_well_formed():
    cat = load_catalogue()
    slugs = [a["slug"] for a in cat["apps"]]
    assert len(slugs) == len(set(slugs)) >= 15
    for a in cat["apps"]:
        assert a["role"] in cat["roles"] and a["tier"] in ("A", "B") and a["status"] in ("verified_claim", "to_verify")
        assert a.get("why") and a.get("verify_at") is not None
    assert {"canary", "vscodium", "vscode", "jan", "gpt4all", "zed", "syncthing"} <= {a["slug"] for a in list_candidates("A")}


def test_every_candidate_generates_a_valid_manifest():
    for a in list_candidates():
        m = parse_manifest(yaml.safe_load(manifest_text_for(a["slug"])))
        assert m.app.slug == a["slug"]
    assert parse_manifest(yaml.safe_load(manifest_text_for("canary"))).capture.mode == "regular"
    with pytest.raises(ClaimCheckError):
        get_candidate("nope")


# ------------------------------------------------------------------ benchmark
def test_benchmark_metrics_and_mismatches():
    truth = {"slug": "x", "expected": {"no_telemetry": "CONTRADICTED", "local_first": "NOT_CONTRADICTED", "optout_effective": "CONTRADICTED"},
             "expected_hosts": {"telemetry": ["eu.i.posthog.com", "o0.ingest.sentry.io"], "benign": ["api.x.test"]}}
    verdicts = {"no_telemetry": "CONTRADICTED", "local_first": "CONTRADICTED", "optout_effective": "WARNING"}
    labels = [{"host": "eu.i.posthog.com", "label": "telemetry_third_party"}, {"host": "api.x.test", "label": "telemetry_first_party"}]
    res = evaluate(truth, verdicts, labels)
    vm, hm = res["verdict_metrics"], res["host_metrics"]
    assert (vm["tp"], vm["fp"], vm["fn"], vm["tn"]) == (1, 1, 1, 0) and vm["precision"] == 0.5 and vm["recall"] == 0.5
    assert (hm["tp"], hm["fn"], hm["fp"]) == (1, 1, 1) and not res["all_match"]
    perfect = evaluate({"slug": "x", "expected": {"no_telemetry": "NOT_CONTRADICTED"}}, {"no_telemetry": "NOT_CONTRADICTED"}, [])
    assert perfect["all_match"] and perfect["verdict_metrics"]["precision"] is None


def test_missing_verdict_is_reported():
    res = evaluate({"slug": "x", "expected": {"no_telemetry": "CONTRADICTED"}}, {}, [])
    assert res["rows"][0]["observed"] == "MISSING" and res["verdict_metrics"]["fn"] == 1


def test_truth_files_shipped_with_repo_load():
    from pathlib import Path

    for f in (Path(__file__).parent.parent / "benchmark/truth").glob("*.yaml"):
        assert load_truth(f)["slug"] == "canary"


def test_benchmark_cli_reports_failure_exit_code(tmp_path):
    from claimcheck.runs import create_run
    from helpers import write_manifest

    root = tmp_path / "runs"
    create_run(root, write_manifest(tmp_path / "m.yaml", app={"name": "canary", "exe_name": "c"}))
    truth = tmp_path / "t.yaml"
    truth.write_text("slug: canary\nexpected: {no_telemetry: CONTRADICTED}\n", encoding="utf-8")
    r = CliRunner().invoke(app, ["benchmark", str(truth), "--runs-root", str(root)])
    assert r.exit_code == 1 and "MISMATCH" in r.output


# ------------------------------------------------------------------ resources
def test_resource_guard_alerts(tmp_path):
    g = ResourceGuard(tmp_path, min_free_disk_mb=10**9, min_free_ram_mb=10**9, max_flows=5)
    alerts = g.check(flows_so_far=5)
    levels = [(a.level, a.message.split()[0]) for a in alerts]
    assert ("abort", "free") in levels and ("warn", "available") in levels and ("abort", "flow") in levels
    assert [a for a in g.check(0) if a.level == "warn"] == []  # RAM warning shown only once
    ok = ResourceGuard(tmp_path, 1, 1, 0)
    assert ok.check(10**6) == [] and set(ok.snapshot()) == {"disk_free_mb", "ram_avail_mb"}


def test_doctor_checks_and_worker_recommendation(tmp_path):
    checks = {c.name: c for c in doctor_checks(tmp_path, "definitely-missing-mitm")}
    assert checks["python"].status == "OK" and checks["mitmdump"].status == "WARN"
    assert {"cpu", "ram", "disk", "administrator", "static workers"} <= set(checks)
    assert 1 <= recommend_static_workers() <= 4
    assert resolve_command("definitely-missing-mitm") is None and resolve_command("") is None
