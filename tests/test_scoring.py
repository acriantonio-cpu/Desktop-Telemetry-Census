from __future__ import annotations

import pytest

from claimcheck.models import V_CONTRADICTED, V_INCONCLUSIVE, V_NOT_CONTRADICTED, V_WARNING
from claimcheck.scoring.checks import Facts, run_checks, summarize


def _label(host="eu.i.posthog.com", label="telemetry_third_party", phase="capture_idle", sdk="posthog", cat="analytics", req=500):
    return {"capture_phase": phase, "host": host, "label": label, "score": 1.0, "sdk_id": sdk, "category": cat, "n_flows": 5, "req_bytes": req, "reasons": ["r"]}


def _claim(kind, text="t", qual=None):
    return {"kind": kind, "text": text, "source_role": "readme", "source_ref": "x", "confidence": 0.8, "detail": {"qualifiers": qual or []}}


def _facts(claims=(), labels=(), static=(), disclosed=(), policy=False, flows=None, sides=()):
    f = Facts()
    for c in claims:
        f.claims.setdefault(c["kind"], []).append(c)
    f.labels, f.static, f.disclosed, f.has_policy = list(labels), list(static), set(disclosed), policy
    f.flows_per_phase = flows if flows is not None else ({"capture_idle": 10} if labels else {})
    f.sides_scanned = set(sides)
    return f


def _by(verdicts, cid):
    return next(v for v in verdicts if v["check_id"] == cid)


def _sdk(side, sdk, kind="sdk_package"):
    return {"side": side, "sdk_id": sdk, "kind": kind, "confidence": 0.9, "location": "x"}


def test_no_claims_yields_explanatory_inconclusive():
    v = run_checks(_facts())
    assert v[0]["check_id"] == "claims_found" and v[0]["verdict"] == V_INCONCLUSIVE


def test_no_telemetry_contradicted_severity_by_party():
    f = _facts([_claim("no_telemetry")], [_label()])
    v = _by(run_checks(f), "no_telemetry")
    assert v["verdict"] == V_CONTRADICTED and v["severity"] == "high"
    f2 = _facts([_claim("no_telemetry")], [_label(label="telemetry_first_party")])
    assert _by(run_checks(f2), "no_telemetry")["severity"] == "medium"


def test_no_telemetry_states_without_data_warning_and_clean():
    assert _by(run_checks(_facts([_claim("no_telemetry")])), "no_telemetry")["verdict"] == V_INCONCLUSIVE
    strong = _facts([_claim("no_telemetry")], static=[_sdk("binary", "sentry")], flows={})
    assert _by(run_checks(strong), "no_telemetry")["verdict"] == V_WARNING
    silent_sdk = _facts([_claim("no_telemetry")], [_label(label="first_party", sdk=None)], static=[_sdk("binary", "sentry")], flows={"capture_idle": 3})
    v = _by(run_checks(silent_sdk), "no_telemetry")
    assert v["verdict"] == V_WARNING and v["severity"] == "low"
    clean = _facts([_claim("no_telemetry")], [_label(label="first_party", sdk=None)], flows={"capture_idle": 3})
    v = _by(run_checks(clean), "no_telemetry")
    assert v["verdict"] == V_NOT_CONTRADICTED and "Not proof" in v["explanation"]
    sus = _facts([_claim("no_telemetry")], [_label(label="suspect")])
    assert _by(run_checks(sus), "no_telemetry")["verdict"] == V_WARNING


def test_qualified_claim_adds_manual_check_note():
    f = _facts([_claim("no_telemetry", qual=["opt-in"])], [_label()])
    assert "qualified" in _by(run_checks(f), "no_telemetry")["explanation"]


def test_third_party_sharing_ignores_first_party_telemetry():
    f = _facts([_claim("no_third_party_sharing")], [_label(label="telemetry_first_party")])
    assert _by(run_checks(f), "no_third_party_sharing")["verdict"] == V_NOT_CONTRADICTED
    f2 = _facts([_claim("no_third_party_sharing")], [_label()])
    assert _by(run_checks(f2), "no_third_party_sharing")["verdict"] == V_CONTRADICTED


def test_local_first_levels():
    warn = _facts([_claim("local_first")], [_label()])
    assert _by(run_checks(warn), "local_first")["verdict"] == V_WARNING
    replay = _facts([_claim("local_first")], [_label(host="x.fullstory.com", sdk="fullstory", cat="session_replay")])
    assert _by(run_checks(replay), "local_first")["verdict"] == V_CONTRADICTED
    upload = _facts([_claim("local_first")], [_label(host="up.other.io", label="unknown", sdk=None, req=200_000)])
    assert _by(run_checks(upload), "local_first")["verdict"] == V_CONTRADICTED
    clean = _facts([_claim("local_first")], [_label(host="api.x.app", label="first_party", sdk=None)], flows={"capture_idle": 2})
    assert _by(run_checks(clean), "local_first")["verdict"] == V_NOT_CONTRADICTED


def test_privacy_friendly_uses_policy_disclosure():
    labels = [_label()]
    no_policy = _facts([_claim("privacy_friendly")], labels, policy=False)
    assert _by(run_checks(no_policy), "privacy_friendly")["verdict"] == V_WARNING
    undisclosed = _facts([_claim("privacy_friendly")], labels, policy=True, disclosed=["sentry"])
    assert _by(run_checks(undisclosed), "privacy_friendly")["verdict"] == V_CONTRADICTED
    disclosed = _facts([_claim("privacy_friendly")], labels, policy=True, disclosed=["posthog"])
    v = _by(run_checks(disclosed), "privacy_friendly")
    assert v["verdict"] == V_WARNING and v["severity"] == "low"
    invasive = _facts([_claim("privacy_friendly")], [_label(sdk="fullstory", cat="session_replay")], policy=True)
    assert _by(run_checks(invasive), "privacy_friendly")["severity"] == "high"


def test_open_source_compares_binary_with_repo():
    need = _facts([_claim("open_source")], static=[_sdk("binary", "sentry")], sides={"binary"})
    assert _by(run_checks(need), "open_source")["verdict"] == V_INCONCLUSIVE
    both = {"binary", "repo"}
    contradicted = _facts([_claim("open_source")], static=[_sdk("binary", "sentry")], sides=both)
    assert _by(run_checks(contradicted), "open_source")["verdict"] == V_CONTRADICTED
    weak = _facts([_claim("open_source")], static=[_sdk("binary", "sentry", "sdk_string")], sides=both)
    assert _by(run_checks(weak), "open_source")["verdict"] == V_WARNING
    ok = _facts([_claim("open_source")], static=[_sdk("binary", "sentry"), _sdk("repo", "sentry", "sdk_dependency")], sides=both)
    assert _by(run_checks(ok), "open_source")["verdict"] == V_NOT_CONTRADICTED


def test_optout_check_only_runs_with_optout_data():
    base = [_label(phase="capture_idle")]
    assert "optout_effective" not in {v["check_id"] for v in run_checks(_facts([], base, flows={"capture_idle": 5}))}
    persists = _facts([], base + [_label(phase="capture_optout")], flows={"capture_idle": 5, "capture_optout": 5})
    assert _by(run_checks(persists), "optout_effective")["verdict"] == V_CONTRADICTED
    stops = _facts([], base + [_label(host="api.x.app", label="first_party", sdk=None, phase="capture_optout")], flows={"capture_idle": 5, "capture_optout": 5})
    assert _by(run_checks(stops), "optout_effective")["verdict"] == V_NOT_CONTRADICTED
    nothing = _facts([], [_label(host="api.x.app", label="first_party", sdk=None, phase="capture_optout")], flows={"capture_optout": 5})
    assert _by(run_checks(nothing), "optout_effective")["verdict"] == V_INCONCLUSIVE


def test_policy_disclosure_generic_check():
    obs = _facts([], [_label()], policy=True, disclosed=["sentry"])
    assert _by(run_checks(obs), "policy_disclosure")["verdict"] == V_CONTRADICTED
    ok = _facts([], [_label()], policy=True, disclosed=["posthog"])
    assert _by(run_checks(ok), "policy_disclosure")["verdict"] == V_NOT_CONTRADICTED
    assert _by(run_checks(_facts([], [_label()], policy=False)), "policy_disclosure")["verdict"] == V_INCONCLUSIVE


def test_summarize_counts():
    assert summarize([{"verdict": "A"}, {"verdict": "A"}, {"verdict": "B"}]) == {"A": 2, "B": 1}


@pytest.mark.parametrize("kind", ["no_telemetry", "local_first", "privacy_friendly", "open_source", "no_third_party_sharing"])
def test_every_claim_kind_yields_exactly_one_verdict_without_data(kind):
    v = [x for x in run_checks(_facts([_claim(kind)])) if x["claim_kind"] == kind]
    assert len(v) == 1 and v[0]["verdict"] in (V_INCONCLUSIVE, V_WARNING, V_NOT_CONTRADICTED)
