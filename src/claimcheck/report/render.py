"""Report generation: one JSON (machine-readable) + one self-contained HTML (human-readable).

Security: captured data is UNTRUSTED (hostnames, payload samples, claim text come from the outside).
Every dynamic value goes through html.escape(); the page ships a strict CSP (no scripts, no network).
"""

from __future__ import annotations

import html
import json
from collections import Counter

from claimcheck import __version__
from claimcheck.context import Context
from claimcheck.models import CAPTURE_PHASES, CAPTURE_SHORT, PHASES
from claimcheck.scoring.checks import collect_quality, summarize
from claimcheck.util import human_bytes, unique_path, utcnow_iso

E = html.escape

VERDICT_ORDER = ["CONTRADICTED", "WARNING", "INCONCLUSIVE", "NOT_CONTRADICTED"]
LABELS_TELE = {"telemetry_third_party", "telemetry_first_party"}

LIMITATIONS = [
    "NOT_CONTRADICTED means 'nothing conflicting was observed in the covered phases', never 'proven clean'.",
    "Only traffic during the captured phases is seen: telemetry triggered by events you did not exercise is missed.",
    "TLS pinning: pinned connections are visible only through SNI + timing (no payload); they cannot be classified by content.",
    "Blocklists/vendor lists are incomplete; new or self-hosted telemetry endpoints rely on behavioural heuristics (weaker).",
    "Static scan is signature-based: obfuscated/renamed SDKs and pnpm/gradle transitive dependencies can cause false negatives/positives.",
    "CNAME lookups reflect DNS at analysis time, which may differ from capture time.",
    "Claim extraction is rule-based: it can miss claims phrased unusually and can over-match marketing prose. Read the source sentence.",
]


def build_report_data(ctx: Context) -> dict:
    st = ctx.store
    m = ctx.manifest
    verdict_ids = st.effective_attempt_ids("score")
    verdicts = st.select("verdicts", verdict_ids)
    labels = st.select("labels", st.effective_attempt_ids("classify"))
    claims = st.select("claims", st.effective_attempt_ids("claims"))
    disclosed = st.select("disclosed", st.effective_attempt_ids("claims"))
    static = st.select("static_evidence", st.effective_attempt_ids("static"))
    dns = st.select("dns_records", st.effective_attempt_ids("classify"))
    attempts = st.attempts()
    from claimcheck.pipeline import is_stale  # local import: pipeline imports this module

    stale = [ph for ph in ("classify", "score") if is_stale(ctx, ph)]
    static_att = st.get_attempt(st.effective_attempt_ids("static")[0]) if st.effective_attempt_ids("static") else None
    phase_status = {p: st.phase_status(p)["status"] for p in PHASES}
    flows_per_phase = {}
    for ph in CAPTURE_PHASES:
        ids = st.effective_attempt_ids(ph)
        if ids:
            marks = ",".join("?" for _ in ids)
            flows_per_phase[ph] = st._one(f"SELECT COUNT(*) AS n FROM flows WHERE attempt_id IN ({marks})", tuple(ids))["n"]  # noqa: S608  # '?' placeholders only  # nosec B608
    return {
        "generated_at": utcnow_iso(), "tool_version": __version__,
        "app": {"name": m.app.name, "version": m.app.version, "stack": m.app.stack, "homepage": m.app.homepage},
        "run": {"app_slug": ctx.run.app_slug, "run_id": ctx.run.run_id, "manifest_sha256": ctx.manifest_sha256},
        "phase_status": phase_status, "flows_per_phase": flows_per_phase,
        "quality_warnings": collect_quality(st, stale), "stale_phases": stale,
        "summary": summarize(verdicts), "verdicts": verdicts, "labels": labels, "claims": claims,
        "disclosed_vendors": disclosed, "static_evidence": static, "dns": dns,
        "static_coverage": (static_att or {}).get("summary", {}).get("coverage", {}),
        "attempts": [{k: a[k] for k in ("id", "phase", "seq", "status", "started_at", "finished_at", "excluded", "note")} for a in attempts],
        "limitations": LIMITATIONS,
    }


CSS = """
:root{--bg:#f6f8fa;--panel:#fff;--ink:#1d2733;--mute:#5b6876;--line:#d7dee6;--red:#b42318;--red-bg:#fdecea;--amb:#8a5a00;--amb-bg:#fff4d6;--grn:#0b6b3a;--grn-bg:#e3f4ea;--gry:#4a5563;--gry-bg:#e9edf2;--mono:ui-monospace,SFMono-Regular,Consolas,monospace}
:root:not([data-theme=light]){color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--bg:#12171d;--panel:#1a212a;--ink:#e6ebf1;--mute:#9aa7b5;--line:#2d3743;--red:#ff8a80;--red-bg:#3a1a18;--amb:#f2c14e;--amb-bg:#3a2d10;--grn:#6fdc9c;--grn-bg:#12301f;--gry:#b3bdc9;--gry-bg:#232c37}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1000px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:1.6rem;margin:0 0 4px}h2{font-size:1.15rem;margin:36px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--line)}
h3{font-size:1rem;margin:0 0 4px}.mute{color:var(--mute)}.small{font-size:.85rem}
.pills{display:flex;flex-wrap:wrap;gap:8px;margin:14px 0}
.pill{padding:4px 12px;border-radius:999px;font-weight:600;font-size:.9rem}
.v-CONTRADICTED{background:var(--red-bg);color:var(--red)}.v-WARNING{background:var(--amb-bg);color:var(--amb)}
.v-NOT_CONTRADICTED{background:var(--grn-bg);color:var(--grn)}.v-INCONCLUSIVE{background:var(--gry-bg);color:var(--gry)}
.card{background:var(--panel);border:1px solid var(--line);border-left-width:5px;border-radius:6px;padding:12px 16px;margin:12px 0}
.card.v-CONTRADICTED{border-left-color:var(--red)}.card.v-WARNING{border-left-color:var(--amb)}
.card.v-NOT_CONTRADICTED{border-left-color:var(--grn)}.card.v-INCONCLUSIVE{border-left-color:var(--gry)}
.card .pill{font-size:.75rem;padding:2px 9px;margin-right:8px}
.tblwrap{overflow-x:auto;max-width:100%}table{border-collapse:collapse;width:100%;font-size:.86rem;margin:8px 0}
th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{font-weight:600;color:var(--mute)}
td.num{text-align:right;font-variant-numeric:tabular-nums}code,.mono{font-family:var(--mono);font-size:.85em;overflow-wrap:anywhere}
ul.plain{margin:6px 0;padding-left:20px}blockquote{margin:6px 0;padding:4px 12px;border-left:3px solid var(--line);color:var(--mute)}
details{margin:8px 0}summary{cursor:pointer;color:var(--mute)}summary:focus-visible,a:focus-visible{outline:2px solid var(--ink);outline-offset:2px}
"""


def _pill(v: str) -> str:
    return f'<span class="pill v-{E(v)}">{E(v.replace("_", " "))}</span>'


def _table(headers: list[str], rows: list[list], num_cols: set[int] | None = None) -> str:
    num_cols = num_cols or set()
    head = "".join(f"<th>{E(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f'<td class="{"num" if i in num_cols else ""}">{c if isinstance(c, _Raw) else E(str(c))}</td>' for i, c in enumerate(r)) + "</tr>"
        for r in rows
    )
    return f'<div class="tblwrap"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


class _Raw(str):
    """Marker for already-escaped HTML fragments."""


def _evidence_html(ev: list[dict]) -> str:
    if not ev:
        return ""
    traffic = [e for e in ev if e["type"] == "traffic"]
    static = [e for e in ev if e["type"] == "static"]
    claims = [e for e in ev if e["type"] == "claim"]
    out = []
    for c in claims[:4]:
        out.append(f'<blockquote>{E(str(c["text"]))} <span class="small">({E(str(c.get("source") or ""))})</span></blockquote>')
    if traffic:
        rows = [[t["phase"], t["host"], t["label"], f'{t["score"]:.2f}', t.get("sdk") or "", t["n_flows"], human_bytes(t["req_bytes"]), _Raw("<br>".join(E(w) for w in t["why"]))] for t in traffic]
        out.append(_table(["phase", "host", "label", "score", "vendor", "n", "sent", "why"], rows, {3, 5, 6}))
    if static:
        rows = [[s["side"], s["sdk"], s["kind"], s["where"]] for s in static]
        out.append(_table(["side", "sdk", "kind", "where"], rows))
    return "<details open><summary>evidence</summary>" + "".join(out) + "</details>"


def render_html(d: dict) -> str:
    app = d["app"]
    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1, viewport-fit=cover'>",
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">",
        f"<title>ClaimCheck report - {E(app['name'])}</title><style>{CSS}</style></head><body><main>",
        f"<h1>{E(app['name'])} {E(app.get('version') or '')}</h1>",
        f"<p class='mute'>Claim-vs-behaviour audit &middot; run <code>{E(d['run']['run_id'])}</code> &middot; generated {E(d['generated_at'])} &middot; claimcheck {E(d['tool_version'])}</p>",
    ]
    counts = d["summary"]
    qw = d.get("quality_warnings") or []
    if qw:  # BEFORE the verdicts: a reader must see how far the verdicts can be trusted
        parts.append("<div class='card v-WARNING'><h3>Data-quality warnings: read before trusting the verdicts</h3><ul class='plain'>"
                     + "".join(f"<li>{E(str(w))}</li>" for w in qw) + "</ul></div>")
    parts.append("<div class='pills'>" + "".join(f"{_pill(v)} <span class='mute' style='align-self:center'>{counts[v]}</span>" for v in VERDICT_ORDER if counts.get(v)) + "</div>")
    if not d["verdicts"]:
        parts.append("<p>No verdicts yet: run <code>claimcheck score</code>.</p>")
    parts.append("<h2>Verdicts</h2>")
    for v in sorted(d["verdicts"], key=lambda x: VERDICT_ORDER.index(x["verdict"]) if x["verdict"] in VERDICT_ORDER else 9):
        parts.append(
            f"<div class='card v-{E(v['verdict'])}'><h3>{_pill(v['verdict'])}{E(v['title'])}</h3>"
            f"<p class='small mute'>check <code>{E(v['check_id'])}</code> &middot; severity {E(str(v.get('severity') or ''))}"
            f"{' &middot; claim <code>' + E(v['claim_kind']) + '</code>' if v.get('claim_kind') else ''}</p>"
            f"<p>{E(v['explanation'])}</p>{_evidence_html(v['evidence'] or [])}</div>"
        )
    # ---- traffic ----
    parts.append("<h2>Observed traffic</h2>")
    if d["labels"]:
        rows = [[CAPTURE_SHORT.get(x["capture_phase"], x["capture_phase"]), x["host"], x["label"], f'{x["score"]:.2f}', x.get("sdk_id") or "", x["n_flows"], human_bytes(x["req_bytes"])] for x in d["labels"]]
        parts.append(_table(["phase", "host", "label", "score", "vendor", "n", "sent"], rows, {3, 5, 6}))
        parts.append("<details><summary>why each host got its label</summary>" + "".join(
            f"<p><b>{E(CAPTURE_SHORT.get(x['capture_phase'], ''))}</b> <code>{E(x['host'])}</code>: " + E("; ".join(x["reasons"])) + "</p>" for x in d["labels"]) + "</details>")
    else:
        parts.append("<p class='mute'>No classified traffic (run capture + classify).</p>")
    fl = d["flows_per_phase"]
    if fl:
        parts.append("<p class='small mute'>Records per phase: " + ", ".join(f"{E(CAPTURE_SHORT[p])}={n}" for p, n in fl.items()) + "</p>")
    # ---- static ----
    parts.append("<h2>Static findings</h2>")
    if d["static_evidence"]:
        by = Counter((e["side"], e["sdk_id"]) for e in d["static_evidence"])
        rows = [[side, sdk, n] for (side, sdk), n in sorted(by.items())]
        parts.append(_table(["side", "sdk", "evidence items"], rows, {2}))
        cov = d.get("static_coverage") or {}
        if cov:
            parts.append("<details><summary>scan coverage (what was NOT looked at)</summary><ul class='plain'>" + "".join(
                f"<li><b>{E(str(side))}</b>: {E(str(c))}</li>" for side, c in [(k, json.dumps(v, ensure_ascii=False)) for k, v in cov.items()]) + "</ul></details>")
    else:
        parts.append("<p class='mute'>No SDK evidence (or static phase not run).</p>")
    # ---- claims & disclosure ----
    parts.append("<h2>Extracted claims</h2>")
    if d["claims"]:
        parts.append(_table(["kind", "sentence", "source", "conf.", "qualifiers"], [[c["kind"], c["text"], c.get("source_role") or "", f'{(c.get("confidence") or 0):.2f}', ", ".join((c.get("detail") or {}).get("qualifiers", []))] for c in d["claims"]], {3}))
    else:
        parts.append("<p class='mute'>No claims extracted.</p>")
    named = [x for x in d["disclosed_vendors"] if x["sdk_id"] != "__generic_telemetry__"]
    if named:
        parts.append("<p>Vendors named in the privacy policy: " + ", ".join(f"<code>{E(x['sdk_id'])}</code>" for x in named) + "</p>")
    if len(named) != len(d["disclosed_vendors"]):
        parts.append("<p class='small mute'>The policy also admits telemetry/analytics in general terms.</p>")
    # ---- provenance ----
    parts.append("<h2>Run history</h2>")
    parts.append(_table(["#", "phase", "attempt", "status", "started", "note"], [[a["id"], a["phase"], a["seq"], a["status"] + (" (excluded)" if a["excluded"] else ""), a["started_at"], a.get("note") or ""] for a in d["attempts"]], {0, 2}))
    parts.append(f"<p class='small mute'>manifest sha256 <code>{E(d['run']['manifest_sha256'][:16])}</code></p>")
    parts.append("<h2>How to read this report</h2><ul class='plain'>" + "".join(f"<li>{E(x)}</li>" for x in d["limitations"]) + "</ul>")
    parts.append("</main></body></html>")
    return "".join(parts)


def write_report(ctx: Context, attempt_seq: int) -> tuple[str, str]:
    """Write report_<n>.html/.json into reports/ (never overwriting). Returns (html_path, json_path)."""
    data = build_report_data(ctx)
    ctx.run.reports_dir.mkdir(parents=True, exist_ok=True)
    stem = f"report_{attempt_seq:03d}"
    html_path = unique_path(ctx.run.reports_dir, stem, ".html")
    json_path = html_path.with_suffix(".json")
    if json_path.exists():  # keep the pair aligned even in the (unlikely) collision case
        json_path = unique_path(ctx.run.reports_dir, html_path.stem, ".json")
    html_path.write_text(render_html(data), encoding="utf-8", newline="\n")
    json_path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8", newline="\n")
    return str(html_path), str(json_path)
