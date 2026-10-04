"""Claim -> testable predicate -> verdict.

Verdict semantics (deliberately asymmetric, to avoid overclaiming):
  CONTRADICTED       observed evidence directly conflicts with the claim
  WARNING            suspicious / partial / qualified; needs a human look
  NOT_CONTRADICTED   nothing observed conflicts with the claim *within the covered phases* (this is NOT proof)
  INCONCLUSIVE       not enough data to test the claim (missing capture/static/policy)
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from claimcheck.models import (
    CAPTURE_PHASES, CAPTURE_SHORT, L_OPAQUE, L_SUSPECT, L_TELEMETRY_3P, L_UNKNOWN, TELEMETRY_LABELS,
    V_CONTRADICTED, V_INCONCLUSIVE, V_NOT_CONTRADICTED, V_WARNING,
)
from claimcheck.store import Store

GENERIC_DISCLOSURE = "__generic_telemetry__"  # keep equal to claims.GENERIC_DISCLOSURE (no import: avoid a cycle)

STRONG_STATIC_KINDS = {"sdk_package", "sdk_dependency", "sdk_filename"}
UPLOAD_WARN_BYTES = 50 * 1024
INVASIVE_CATEGORIES = {"ad_tracking", "session_replay"}


@dataclass
class Facts:
    claims: dict = field(default_factory=dict)  # kind -> [claim rows]
    labels: list = field(default_factory=list)
    static: list = field(default_factory=list)
    disclosed: set = field(default_factory=set)
    has_policy: bool = False
    flows_per_phase: dict = field(default_factory=dict)  # phase -> record count
    sides_scanned: set = field(default_factory=set)
    static_coverage: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)
    quality: list = field(default_factory=list)  # data-quality warnings (also shown as a banner in the report)
    policy_unusable: bool = False  # a privacy_policy was fetched but is empty / a bot wall / a JS shell

    # ---- data-quality helpers ----------------------------------------------
    def has_traffic(self) -> bool:
        """True only if at least one record was really captured. A capture attempt with 0 records is NOT evidence of silence."""
        return sum(self.flows_per_phase.values()) > 0

    def static_gaps(self) -> list[str]:
        """Reasons the static scan is incomplete: 'nothing found' must not be read as 'nothing there'."""
        out = []
        for side, cov in (self.static_coverage or {}).items():
            if not isinstance(cov, dict):
                continue
            for key, what in (("skipped_size", "files over the size limit"), ("skipped_budget", "files beyond the byte budget"),
                              ("opaque_container_count", "compressed containers / installers (not inspectable)")):
                if cov.get(key):
                    out.append(f"{side}: {cov[key]} {what}")
            if cov.get("errors"):
                out.append(f"{side}: {len(cov['errors'])} file(s) could not be read")
        return out

    # ---- helpers --------------------------------------------------------
    def phases_with_data(self) -> list[str]:
        return [p for p in CAPTURE_PHASES if self.flows_per_phase.get(p, 0) > 0]

    def tele(self, phases=None, third_party_only=False) -> list[dict]:
        wanted = TELEMETRY_LABELS if not third_party_only else (L_TELEMETRY_3P,)
        return [x for x in self.labels if x["label"] in wanted and (phases is None or x["capture_phase"] in phases)]

    def suspects(self) -> list[dict]:
        return [x for x in self.labels if x["label"] == L_SUSPECT]

    def static_sdks(self, side: str, strong_only: bool = False) -> dict[str, list[dict]]:
        out: dict[str, list[dict]] = defaultdict(list)
        for e in self.static:
            if e["side"] == side and (not strong_only or e["kind"] in STRONG_STATIC_KINDS):
                out[e["sdk_id"]].append(e)
        return out


def build_facts(store: Store, stale: list[str] | None = None) -> Facts:
    f = Facts()
    claim_ids = store.effective_attempt_ids("claims")
    for c in store.select("claims", claim_ids):
        f.claims.setdefault(c["kind"], []).append(c)
    f.disclosed = {d["sdk_id"] for d in store.select("disclosed", claim_ids)}
    claims_attempt = store.get_attempt(claim_ids[0]) if claim_ids else None
    csum = (claims_attempt or {}).get("summary") or {}
    f.has_policy = bool(csum.get("policy_docs_loaded", 0) > 0)
    f.policy_unusable = bool(csum.get("policy_docs_unusable", 0) > 0)
    static_ids = store.effective_attempt_ids("static")
    f.static = store.select("static_evidence", static_ids)
    if static_ids:
        att = store.get_attempt(static_ids[0]) or {}
        summ = att.get("summary") or {}
        f.sides_scanned = set(summ.get("sides", []))
        f.static_coverage = summ.get("coverage", {})
    cls_ids = store.effective_attempt_ids("classify")
    f.labels = store.select("labels", cls_ids)
    for ph in CAPTURE_PHASES:
        ids = store.effective_attempt_ids(ph)
        if ids:
            marks = ",".join("?" for _ in ids)
            row = store._one(f"SELECT COUNT(*) AS n FROM flows WHERE attempt_id IN ({marks})", tuple(ids))  # noqa: S608  # '?' placeholders only  # nosec B608
            f.flows_per_phase[ph] = row["n"] if row else 0
    if not cls_ids and f.flows_per_phase:
        f.notes.append("capture data exists but the 'classify' phase has not been run: run `claimcheck classify` then `score`")
    f.quality = collect_quality(store, stale)
    return f


def _summary_of(store: Store, phase: str) -> dict:
    ids = store.effective_attempt_ids(phase)
    return ((store.get_attempt(ids[0]) or {}).get("summary") or {}) if ids else {}


def collect_quality(store: Store, stale: list[str] | None = None) -> list[str]:
    """Everything that makes a verdict less trustworthy. Shown in `score` output AND as a banner in the report."""
    q: list[str] = []
    for ph in CAPTURE_PHASES:
        ids = store.effective_attempt_ids(ph)
        if not ids:
            continue
        marks = ",".join("?" for _ in ids)
        n = store._one(f"SELECT COUNT(*) AS n FROM flows WHERE attempt_id IN ({marks})", tuple(ids))["n"]  # noqa: S608  # '?' placeholders only  # nosec B608
        short = CAPTURE_SHORT[ph]
        if n == 0:
            q.append(f"capture '{short}' recorded 0 records: this is NOT evidence that the app was silent (CA not trusted? wrong exe_name? proxy not used?)")
        for a in store.attempts(ph):
            if a["id"] in ids and a["status"] == "partial":
                q.append(f"capture '{short}' attempt #{a['seq']} is partial ({a.get('note') or 'stopped early'}): shorter observation window")
    csum = _summary_of(store, "classify")
    if csum.get("dns_unavailable") or csum.get("dns_skipped"):
        q.append(f"CNAME-cloaking check not performed for {csum.get('dns_skipped', 0)} host(s) (DNS unavailable or lookup limit reached)")
    ssum = _summary_of(store, "static")
    for gap in Facts(static_coverage=ssum.get("coverage", {})).static_gaps():
        q.append("static scan incomplete - " + gap)
    info = ssum.get("repo_info") or {}
    if info.get("version_match") is False:
        q.append(f"source repo ({info.get('describe') or str(info.get('commit', '?'))[:12]}) does not look like the installed version: "
                 "binary-vs-source comparison may be wrong")
    clsum = _summary_of(store, "claims")
    if clsum.get("policy_docs_unusable"):
        q.append("a privacy policy was fetched but looks empty / bot-check / JS shell: disclosure checks skipped")
    for w in (clsum.get("doc_warnings") or [])[:5]:
        q.append("document: " + str(w))
    if clsum.get("docs_failed"):
        q.append(f"{clsum['docs_failed']} configured document(s) could not be loaded")
    for ph in stale or []:
        q.append(f"'{ph}' results are older than their inputs (exclude/include, new capture or edited manifest): re-run `claimcheck resume`")
    return q


def _ev_label(x: dict) -> dict:
    return {"type": "traffic", "phase": CAPTURE_SHORT.get(x["capture_phase"], x["capture_phase"]), "host": x["host"],
            "label": x["label"], "score": x["score"], "sdk": x.get("sdk_id"), "category": x.get("category"),
            "n_flows": x["n_flows"], "req_bytes": x["req_bytes"], "why": x["reasons"][:4]}


def _ev_static(e: dict) -> dict:
    return {"type": "static", "side": e["side"], "sdk": e["sdk_id"], "kind": e["kind"], "where": e["location"]}


def _coverage_text(f: Facts) -> str:
    parts = []
    if f.flows_per_phase:
        parts.append("traffic covered: " + ", ".join(f"{CAPTURE_SHORT[p]}={n} records" for p, n in f.flows_per_phase.items()))
    if f.sides_scanned:
        parts.append("static covered: " + ", ".join(sorted(f.sides_scanned)))
    return "; ".join(parts) or "no data collected yet"


def _qualified_note(claims: list[dict]) -> str:
    q = sorted({x for c in claims for x in ((c.get("detail") or {}).get("qualifiers") or [])})
    return f" NOTE: the claim is qualified ({', '.join(q)}): verify manually whether the traffic happened before consent." if q else ""


def _v(check_id, kind, verdict, severity, title, explanation, evidence=None) -> dict:
    return {"check_id": check_id, "claim_kind": kind, "verdict": verdict, "severity": severity, "title": title,
            "explanation": explanation, "evidence": evidence or []}


def _claim_evidence(claims: list[dict]) -> list[dict]:
    return [{"type": "claim", "text": c["text"], "source": c.get("source_role"), "ref": c.get("source_ref"), "confidence": c.get("confidence")} for c in claims]


def _opacity_gate(f: Facts, check_id: str, kind: str | None, ce: list[dict], q: str) -> dict | None:
    """Called just before a NOT_CONTRADICTED verdict: is 'nothing seen' really meaningful?"""
    if not f.labels:
        return _v(check_id, kind, V_INCONCLUSIVE, "info", "Traffic was captured but not classified",
                  "Run `claimcheck classify` (and `score`) so the captured records can be judged." + q, ce)
    inspected = [x for x in f.labels if not (x.get("features") or {}).get("opaque_only")]
    opaque = [x for x in f.labels if x["label"] == L_OPAQUE]
    if not inspected:
        hosts = ", ".join(sorted({x["host"] for x in f.labels})[:6])
        return _v(check_id, kind, V_INCONCLUSIVE, "info", "Traffic could not be inspected (TLS pinning or CA not trusted)",
                  f"Only SNI/timing is visible for: {hosts}. Payloads were never seen, so nothing can be concluded. "
                  "Check that the mitmproxy CA is trusted (docs/02) or test with the canary first." + q, ce + [_ev_label(x) for x in f.labels[:8]])
    if opaque:
        return _v(check_id, kind, V_WARNING, "low", "Some hosts were contacted over traffic that could not be inspected",
                  "No telemetry was recognised in the inspectable traffic, but these third-party hosts are opaque: "
                  + ", ".join(sorted({x["host"] for x in opaque})[:6]) + ". Verify them manually." + q, ce + [_ev_label(x) for x in opaque[:8]])
    return None


# ------------------------------------------------------------------ per-claim checks
def check_no_telemetry(f: Facts, claims: list[dict]) -> dict:
    ce = _claim_evidence(claims)
    tele = f.tele()
    q = _qualified_note(claims)
    if tele:
        third = [x for x in tele if x["label"] == L_TELEMETRY_3P]
        hosts = sorted({x["host"] for x in tele})
        sev = "high" if third else "medium"
        return _v("no_telemetry", "no_telemetry", V_CONTRADICTED, sev, "Claim 'no telemetry' contradicted by observed traffic",
                  f"Telemetry-like traffic observed to {len(hosts)} host(s): {', '.join(hosts[:6])}." + q, ce + [_ev_label(x) for x in tele[:12]])
    sus = f.suspects()
    if sus:
        return _v("no_telemetry", "no_telemetry", V_WARNING, "medium", "Suspicious traffic that may be telemetry",
                  f"{len(sus)} host(s) scored as suspect (below the telemetry threshold): {', '.join(sorted({x['host'] for x in sus})[:6])}." + q,
                  ce + [_ev_label(x) for x in sus[:12]])
    strong = f.static_sdks("binary", strong_only=True)
    if not f.has_traffic():
        if strong:
            return _v("no_telemetry", "no_telemetry", V_WARNING, "low", "Telemetry SDK present in the app, but no traffic captured yet",
                      f"SDK(s) found statically: {', '.join(sorted(strong))}. Run the capture phases to see if they are active." + q,
                      ce + [_ev_static(e) for es in strong.values() for e in es[:2]])
        return _v("no_telemetry", "no_telemetry", V_INCONCLUSIVE, "info", "No traffic captured: claim not testable yet",
                  "Run `claimcheck capture --phase idle` (and `use`) first." + q, ce)
    if strong:
        return _v("no_telemetry", "no_telemetry", V_WARNING, "low", "Telemetry SDK present but no telemetry traffic observed",
                  f"SDK(s) {', '.join(sorted(strong))} are shipped but were silent in the captured phases (dormant, opt-in, or triggered by events not exercised)." + q,
                  ce + [_ev_static(e) for es in strong.values() for e in es[:2]])
    gate = _opacity_gate(f, "no_telemetry", "no_telemetry", ce, q)
    if gate:
        return gate
    return _v("no_telemetry", "no_telemetry", V_NOT_CONTRADICTED, "info", "No telemetry observed in the covered phases",
              f"Not proof of absence. {_coverage_text(f)}." + q, ce)


def check_no_third_party(f: Facts, claims: list[dict]) -> dict:
    ce = _claim_evidence(claims)
    third = f.tele(third_party_only=True)
    q = _qualified_note(claims)
    if third:
        return _v("no_third_party_sharing", "no_third_party_sharing", V_CONTRADICTED, "high", "Traffic to third-party telemetry/tracking hosts observed",
                  f"Hosts: {', '.join(sorted({x['host'] for x in third})[:6])}." + q, ce + [_ev_label(x) for x in third[:12]])
    if not f.has_traffic():
        return _v("no_third_party_sharing", "no_third_party_sharing", V_INCONCLUSIVE, "info", "No traffic captured: claim not testable yet", "Run the capture phases." + q, ce)
    gate = _opacity_gate(f, "no_third_party_sharing", "no_third_party_sharing", ce, q)
    if gate:
        return gate
    return _v("no_third_party_sharing", "no_third_party_sharing", V_NOT_CONTRADICTED, "info", "No third-party telemetry observed in the covered phases",
              f"Note: this only tests telemetry/tracking hosts, not every possible data flow. {_coverage_text(f)}." + q, ce)


def check_local_first(f: Facts, claims: list[dict]) -> dict:
    ce = _claim_evidence(claims)
    q = _qualified_note(claims)
    if not f.has_traffic():
        return _v("local_first", "local_first", V_INCONCLUSIVE, "info", "No traffic captured: claim not testable yet", "Run the capture phases." + q, ce)
    invasive = [x for x in f.tele() if x.get("category") in INVASIVE_CATEGORIES]
    big = [x for x in f.labels if x["label"] in (L_TELEMETRY_3P, L_SUSPECT, L_UNKNOWN) and x["req_bytes"] >= UPLOAD_WARN_BYTES]
    if invasive or (big and any(x["capture_phase"] == "capture_idle" for x in big)):
        items = invasive or big
        return _v("local_first", "local_first", V_CONTRADICTED, "high", "Possible off-device data flow contradicts 'local-first'",
                  "Session-replay/ad-tracking vendor contacted, or large uploads to a non-first-party host while idle: "
                  + ", ".join(sorted({x['host'] for x in items})[:6]) + "." + q, ce + [_ev_label(x) for x in items[:12]])
    tele = f.tele()
    if tele or big:
        items = tele or big
        return _v("local_first", "local_first", V_WARNING, "medium", "Outbound telemetry/uploads exist: inspect what they carry",
                  "Local-first does not forbid telemetry, but the payload must not contain user content. Hosts: "
                  + ", ".join(sorted({x['host'] for x in items})[:6]) + "." + q, ce + [_ev_label(x) for x in items[:12]])
    gate = _opacity_gate(f, "local_first", "local_first", ce, q)
    if gate:
        return gate
    return _v("local_first", "local_first", V_NOT_CONTRADICTED, "info", "No off-device data flow observed in the covered phases",
              f"{_coverage_text(f)}. Only tests network behaviour; sync features you did not exercise are not covered." + q, ce)


def _undisclosed(f: Facts, tele: list[dict]) -> list[dict]:
    """Hosts of a KNOWN vendor that the policy never names (the strong finding)."""
    return [x for x in tele if x.get("sdk_id") and x["sdk_id"] not in f.disclosed]


def _unknown_vendor(f: Facts, tele: list[dict]) -> list[dict]:
    """Telemetry-like hosts with no known vendor (typically self-hosted): only a MANUAL check is possible, unless the
    policy admits telemetry in general terms."""
    if GENERIC_DISCLOSURE in f.disclosed:
        return []
    return [x for x in tele if not x.get("sdk_id")]


def check_privacy_friendly(f: Facts, claims: list[dict]) -> dict:
    ce = _claim_evidence(claims)
    q = _qualified_note(claims)
    third = f.tele(third_party_only=True)
    if not f.has_traffic():
        return _v("privacy_friendly", "privacy_friendly", V_INCONCLUSIVE, "info", "No traffic captured: vague claim not testable yet", "Run the capture phases." + q, ce)
    if not third:
        gate = _opacity_gate(f, "privacy_friendly", "privacy_friendly", ce, q)
        if gate:
            return gate
        return _v("privacy_friendly", "privacy_friendly", V_NOT_CONTRADICTED, "info", "No third-party telemetry observed in the covered phases",
                  f"'Privacy-friendly' is vague; this tests only third-party telemetry/tracking. {_coverage_text(f)}." + q, ce)
    if not f.has_policy:
        return _v("privacy_friendly", "privacy_friendly", V_WARNING, "medium", "Third-party telemetry observed and no privacy policy loaded to compare",
                  f"Hosts: {', '.join(sorted({x['host'] for x in third})[:6])}. Add a privacy_policy document to the manifest." + q, ce + [_ev_label(x) for x in third[:12]])
    und = _undisclosed(f, third)
    if und:
        sev = "high" if any(x.get("category") in INVASIVE_CATEGORIES for x in und) else "medium"
        return _v("privacy_friendly", "privacy_friendly", V_CONTRADICTED, sev, "Third-party telemetry NOT disclosed in the privacy policy",
                  f"Undisclosed: {', '.join(sorted({x['host'] for x in und})[:6])}." + q, ce + [_ev_label(x) for x in und[:12]])
    unk = _unknown_vendor(f, third)
    if unk:
        return _v("privacy_friendly", "privacy_friendly", V_WARNING, "medium", "Third-party telemetry to unrecognised hosts; policy has no general disclosure",
                  f"Hosts: {', '.join(sorted({x['host'] for x in unk})[:6])}. Read the policy manually." + q, ce + [_ev_label(x) for x in unk[:12]])
    return _v("privacy_friendly", "privacy_friendly", V_WARNING, "low", "Third-party telemetry exists but is disclosed in the policy",
              "Disclosed telemetry is not hidden, but it sits uneasily with a 'privacy-friendly' headline; judge proportionality manually." + q,
              ce + [_ev_label(x) for x in third[:12]])


def check_open_source(f: Facts, claims: list[dict]) -> dict:
    ce = _claim_evidence(claims)
    if not {"binary", "repo"} <= f.sides_scanned:
        missing = sorted({"binary", "repo"} - f.sides_scanned)
        return _v("open_source", "open_source", V_INCONCLUSIVE, "info", "Cannot compare binary and source",
                  f"Missing static side(s): {', '.join(missing)}. Set app.install_dir and sources.repo_path (same tag as the release) and run `claimcheck static`.", ce)
    binary, repo = f.static_sdks("binary"), f.static_sdks("repo")
    only = {sid: es for sid, es in binary.items() if sid not in repo}
    strong_only = {sid: es for sid, es in only.items() if any(e["kind"] in STRONG_STATIC_KINDS for e in es)}
    if strong_only:
        return _v("open_source", "open_source", V_CONTRADICTED, "medium", "Shipped binary contains telemetry SDK(s) absent from the published source",
                  f"SDK(s) only in binary: {', '.join(sorted(strong_only))}. Verify the repo tag matches the release and that pnpm/gradle transitive deps are not the cause (limitation).",
                  ce + [_ev_static(e) for es in strong_only.values() for e in es[:2]])
    if only:
        return _v("open_source", "open_source", V_WARNING, "low", "Vendor strings in the binary with no counterpart in the source",
                  f"String-level matches only ({', '.join(sorted(only))}): may be documentation strings or bundled third-party code.",
                  ce + [_ev_static(e) for es in only.values() for e in es[:2]])
    gaps = f.static_gaps()
    if gaps:
        return _v("open_source", "open_source", V_INCONCLUSIVE, "info", "Static scan incomplete: cannot conclude",
                  "No mismatch found, but parts of the app were NOT inspected (" + "; ".join(gaps[:4]) + "). Raise static.max_file_mb / max_total_mb "
                  "or point static at the unpacked installation.", ce)
    return _v("open_source", "open_source", V_NOT_CONTRADICTED, "info", "Every telemetry SDK found in the binary is also present in the source",
              f"{len(binary)} SDK(s) in binary, {len(repo)} in source. {_coverage_text(f)}.", ce)


CLAIM_CHECKS = {
    "no_telemetry": check_no_telemetry,
    "no_third_party_sharing": check_no_third_party,
    "local_first": check_local_first,
    "privacy_friendly": check_privacy_friendly,
    "open_source": check_open_source,
}


# ------------------------------------------------------------------ claim-independent checks
def check_optout(f: Facts) -> dict | None:
    if not f.flows_per_phase.get("capture_optout"):
        return None
    base = f.tele(phases={"capture_idle", "capture_use"})
    after = f.tele(phases={"capture_optout"})
    if after:
        return _v("optout_effective", None, V_CONTRADICTED, "high", "Telemetry continues after opting out",
                  f"Telemetry-like traffic in the opt-out phase to: {', '.join(sorted({x['host'] for x in after})[:6])}. Verify you really disabled it in settings.",
                  [_ev_label(x) for x in after[:12]])
    if base:
        return _v("optout_effective", None, V_NOT_CONTRADICTED, "info", "No telemetry observed after opting out",
                  f"Baseline had telemetry to {', '.join(sorted({x['host'] for x in base})[:4])}; none in the opt-out phase.", [_ev_label(x) for x in base[:6]])
    return _v("optout_effective", None, V_INCONCLUSIVE, "info", "Opt-out effect cannot be assessed",
              "No telemetry was observed in the baseline phases, so there is nothing to switch off.")


def check_disclosure(f: Facts) -> dict:
    tele = f.tele()
    if not f.has_policy:
        why = ("A privacy policy was fetched but looks empty, a bot-check or a JavaScript shell (see data-quality warnings): "
               "it cannot be used." if f.policy_unusable else "Add a document with role privacy_policy to sources.documents to test disclosure.")
        return _v("policy_disclosure", None, V_INCONCLUSIVE, "info", "No privacy policy loaded", why)
    if not f.has_traffic():
        return _v("policy_disclosure", None, V_INCONCLUSIVE, "info", "No traffic captured: disclosure not testable yet", "Run the capture phases.")
    if not tele:
        gate = _opacity_gate(f, "policy_disclosure", None, [], "")
        if gate:
            return gate
        return _v("policy_disclosure", None, V_NOT_CONTRADICTED, "info", "No telemetry observed, nothing to disclose", _coverage_text(f) + ".")
    und = _undisclosed(f, tele)
    if und:
        return _v("policy_disclosure", None, V_CONTRADICTED, "medium", "Observed telemetry vendors are not named in the privacy policy",
                  "Undisclosed: " + ", ".join(sorted({x["sdk_id"] for x in und})[:8]) + ".", [_ev_label(x) for x in und[:12]])
    unk = _unknown_vendor(f, tele)
    if unk:
        return _v("policy_disclosure", None, V_WARNING, "medium", "Telemetry to unrecognised hosts; the policy does not admit telemetry in general terms",
                  "Hosts: " + ", ".join(sorted({x["host"] for x in unk})[:8]) + ". No known vendor: read the policy manually.", [_ev_label(x) for x in unk[:12]])
    return _v("policy_disclosure", None, V_NOT_CONTRADICTED, "info", "Observed telemetry is covered by the privacy policy", _coverage_text(f) + ".")


def run_checks(f: Facts) -> list[dict]:
    out: list[dict] = []
    if not f.claims:
        out.append(_v("claims_found", None, V_INCONCLUSIVE, "info", "No marketing claims extracted",
                      "Add README/homepage/privacy_policy documents to the manifest and run `claimcheck claims`. Generic checks below still run."))
    for kind, claims in f.claims.items():
        fn = CLAIM_CHECKS.get(kind)
        if fn:
            out.append(fn(f, claims))
    for gen in (check_optout, check_disclosure):
        v = gen(f)
        if v:
            out.append(v)
    for n in f.notes:
        out.append(_v("note", None, V_INCONCLUSIVE, "info", "Note", n))
    for n in f.quality:
        out.append(_v("data_quality", None, V_INCONCLUSIVE, "info", "Data-quality warning", n))
    return out


def summarize(verdicts: list[dict]) -> dict:
    counts: dict[str, int] = defaultdict(int)
    for v in verdicts:
        counts[v["verdict"]] += 1
    return dict(counts)
