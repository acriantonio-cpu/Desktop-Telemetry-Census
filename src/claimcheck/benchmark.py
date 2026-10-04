"""Benchmark: compare the tool's verdicts/labels with manually verified ground truth files.

Truth file (YAML): slug, scenario, expected: {check_id: VERDICT}, expected_hosts: {telemetry: [...], benign: [...]}.
`evaluate` returns per-item rows and aggregate precision/recall (positive class = CONTRADICTED / telemetry).
"""

from __future__ import annotations

from pathlib import Path

import yaml

from claimcheck.models import TELEMETRY_LABELS, V_CONTRADICTED
from claimcheck.store import Store
from claimcheck.util import domain_matches


def load_truth(path: Path) -> dict:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if "slug" not in data:
        raise ValueError(f"{path}: truth file needs 'slug'")
    data.setdefault("expected", {})
    data.setdefault("expected_hosts", {})
    return data


def observed_from_store(store: Store) -> tuple[dict[str, str], list[dict]]:
    ids = store.effective_attempt_ids("score")
    verdicts = {v["check_id"]: v["verdict"] for v in store.select("verdicts", ids)}
    labels = store.select("labels", store.effective_attempt_ids("classify"))
    return verdicts, labels


def evaluate(truth: dict, verdicts: dict[str, str], labels: list[dict]) -> dict:
    rows, tp, fp, fn, tn = [], 0, 0, 0, 0
    for check, exp in truth["expected"].items():
        obs = verdicts.get(check, "MISSING")
        ok = obs == exp
        rows.append({"level": "verdict", "item": check, "expected": exp, "observed": obs, "match": ok})
        pos_e, pos_o = exp == V_CONTRADICTED, obs == V_CONTRADICTED
        tp += pos_e and pos_o
        fp += (not pos_e) and pos_o
        fn += pos_e and (not pos_o)
        tn += (not pos_e) and (not pos_o)
    htp = hfp = hfn = htn = 0
    eh = truth.get("expected_hosts", {})
    for host in eh.get("telemetry", []) or []:
        hit = any(domain_matches(x["host"], host) and x["label"] in TELEMETRY_LABELS for x in labels)
        rows.append({"level": "host", "item": host, "expected": "telemetry", "observed": "telemetry" if hit else "not flagged", "match": hit})
        htp += hit
        hfn += not hit
    for host in eh.get("benign", []) or []:
        flagged = any(domain_matches(x["host"], host) and x["label"] in TELEMETRY_LABELS for x in labels)
        rows.append({"level": "host", "item": host, "expected": "benign", "observed": "FLAGGED" if flagged else "not flagged", "match": not flagged})
        hfp += flagged
        htn += not flagged

    def ratio(a, b):
        return round(a / b, 3) if b else None

    return {
        "rows": rows,
        "verdict_metrics": {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn)},
        "host_metrics": {"tp": htp, "fp": hfp, "fn": hfn, "tn": htn, "precision": ratio(htp, htp + hfp), "recall": ratio(htp, htp + hfn)},
        "all_match": all(r["match"] for r in rows),
    }
