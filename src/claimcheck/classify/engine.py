"""Behavioural classification of observed traffic (per capture phase and host).

No single signal decides. Weighted evidence is summed (capped at 1.0) and every contribution is kept
as a human-readable *reason*, so a verdict can always be traced back ("why is this telemetry?").

  vendor domain / CNAME->vendor : strong      blocklist : medium
  payload shape (event/distinct_id/properties...), persistent hashed identifier reuse,
  periodic beacons, small uniform POSTs, telemetry-like host/path words : weak but additive

Encrypted/pinned flows (kind sni/tls_failed) still get vendor/blocklist/periodicity signals from
SNI + timing, but never payload signals - they are labelled accordingly (limitation, see docs).
"""

from __future__ import annotations

import re
import statistics
import time
from collections import Counter, defaultdict
from collections.abc import Callable

from claimcheck.classify.blocklists import Blocklist
from claimcheck.manifest import Manifest
from claimcheck.models import (
    L_ALLOWED, L_FIRST_PARTY, L_OPAQUE, L_SUSPECT, L_TELEMETRY_1P, L_TELEMETRY_3P, L_UNKNOWN,
)
from claimcheck.signatures import SignatureSet
from claimcheck.util import domain_matches, is_ip, normalize_host, registrable_domain, utcnow_iso

TELEMETRY_KEYS = {
    "event", "events", "event_name", "event_type", "distinct_id", "distinctid", "anonymous_id", "anonymousid",
    "session_id", "sessionid", "device_id", "deviceid", "machine_id", "machineid", "install_id", "installid",
    "client_id", "clientid", "cid", "tid", "uuid", "properties", "context", "traits", "app_version", "appversion",
    "os_version", "osversion", "sdk", "sdk_version", "platform", "breadcrumbs", "exception", "user_agent",
    "telemetry", "metrics", "batch", "timestamp", "sent_at", "api_key", "write_key", "measurement_id", "dsn",
}
HOST_HINT = re.compile(r"(^|[.\-])(telemetry|analytics|metrics|tracking|tracker|stats|crash|crashes|sentry|beacon|collect|ingest|otel|diagnostics?)([.\-]|$)")
PATH_HINT = re.compile(r"/(collect|track|tracking|telemetry|analytics|metrics|events?|batch|capture|envelope|beacon|ingest|logs?|report|crash|minidump|usage|stats|newdata)(/|$)")

DNS_MAX_CONSECUTIVE_FAILURES = 5  # offline / blocked resolver: stop instead of waiting timeout x max_dns_lookups
DNS_BUDGET_SECONDS = 90.0

W = {
    "vendor": 0.90, "cname_vendor": 0.85, "blocklist": 0.60, "host_hint": 0.15, "path_hint": 0.20,
    "keys3": 0.35, "keys2": 0.20, "keys1": 0.05, "persistent_id": 0.20, "periodic": 0.15, "uniform_posts": 0.10,
}


def _cov(values: list[float]) -> float | None:
    if len(values) < 2:
        return None
    m = statistics.fmean(values)
    return (statistics.pstdev(values) / m) if m > 0 else None


def _key_names(payload_keys: list[str]) -> set[str]:
    out = set()
    for k in payload_keys:
        last = k.replace("[]", "").split(".")[-1].lower()
        if last in TELEMETRY_KEYS:
            out.add(last)
    return out


def classify_flows(
    flows: list[dict], manifest: Manifest, sigs: SignatureSet, blocklist: Blocklist,
    resolver: Callable[[str], tuple[list[str], str]] | None, log: Callable[[str, str], None],
    notes: dict | None = None,
) -> tuple[list[dict], list[dict]]:
    """Return (label_rows, dns_rows). Rows have no attempt_id (caller adds it).

    `notes` (optional, mutated): dns_unavailable / dns_skipped_hosts / dns_budget_exceeded - so that a CNAME-cloaking
    check that could not run is REPORTED instead of looking like "no cloaking found".
    """
    notes = notes if notes is not None else {}
    notes.update({"dns_unavailable": False, "dns_skipped_hosts": [], "dns_limit_reached": False})
    dns_fail_streak, dns_t0 = 0, time.monotonic()
    cfg = manifest.classify
    first_party = {registrable_domain(d) for d in manifest.first_party_domains}
    allowed = manifest.allowed_domains

    # global identifier reuse: hash -> number of flows carrying it
    id_flow_counts: Counter = Counter()
    for f in flows:
        for h in set(f.get("id_hashes") or []):
            id_flow_counts[h] += 1

    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for f in flows:
        host = normalize_host(f.get("host") or f.get("sni") or "")
        if host:
            groups[(f["capture_phase"], host)].append(f)

    dns_rows: list[dict] = []
    dns_cache: dict[str, tuple[list[str], str]] = {}
    lookups = 0
    labels: list[dict] = []

    for (phase, host), fl in sorted(groups.items(), key=lambda kv: (kv[0][0], -len(kv[1]), kv[0][1])):
        reasons: list[str] = []
        score = 0.0
        sdk_id, category = None, None
        n = len(fl)
        opaque_only = all(x["kind"] in ("sni", "tls_failed") for x in fl)
        is_1p = registrable_domain(host) in first_party or any(domain_matches(host, d) for d in manifest.first_party_domains)
        is_allowed = any(domain_matches(host, d) for d in allowed)

        vendor = sigs.match_domain(host)
        strong = False
        if vendor:
            score += W["vendor"]
            sdk_id, category, strong = vendor.id, vendor.category, True
            reasons.append(f"host matches telemetry vendor '{vendor.name}' ({vendor.category})")
        blk = blocklist.match(host) if len(blocklist) else None
        if blk:
            score += W["blocklist"]
            strong = True
            reasons.append(f"host is in a tracker blocklist: {blk}")

        # ---- CNAME cloaking (only for first-party-looking or hinted hosts) ----
        cname_chain: list[str] = []
        if cfg.resolve_cname and resolver and not is_ip(host) and not vendor and (is_1p or HOST_HINT.search(host)):
            if host in dns_cache:
                cname_chain, err = dns_cache[host]
            elif notes["dns_unavailable"] or lookups >= cfg.max_dns_lookups or time.monotonic() - dns_t0 > DNS_BUDGET_SECONDS:
                if lookups >= cfg.max_dns_lookups:
                    notes["dns_limit_reached"] = True
                elif not notes["dns_unavailable"]:
                    notes["dns_unavailable"] = True  # time budget exhausted
                notes["dns_skipped_hosts"].append(host)
            else:
                lookups += 1
                cname_chain, err = resolver(host)
                dns_cache[host] = (cname_chain, err)
                dns_rows.append({"host": host, "cname_chain": cname_chain, "error": err, "resolved_at": utcnow_iso()})
                dns_fail_streak = dns_fail_streak + 1 if err not in ("", "nxdomain", "cname loop") else 0
                if dns_fail_streak >= DNS_MAX_CONSECUTIVE_FAILURES:
                    notes["dns_unavailable"] = True
                    log("WARN", f"DNS resolver failing ({err}) {dns_fail_streak} times in a row: CNAME-cloaking checks stopped")
            for target in cname_chain:
                tv = sigs.match_domain(target)
                tb = blocklist.match(target) if len(blocklist) else None
                if tv or tb:
                    score += W["cname_vendor"]
                    strong = True
                    sdk_id = sdk_id or (tv.id if tv else None)
                    category = category or (tv.category if tv else "tracker")
                    reasons.append(f"CNAME cloaking: {host} -> {' -> '.join(cname_chain)} matches "
                                   f"{tv.name if tv else tb}")
                    break

        # ---- weak behavioural signals -------------------------------------
        http_flows = [x for x in fl if x["kind"] in ("http", "error")]
        paths = Counter((x.get("path") or "") for x in http_flows)
        keys: set[str] = set()
        for x in http_flows:
            keys |= _key_names(x.get("payload_keys") or [])
        if HOST_HINT.search(host):
            score += W["host_hint"]
            reasons.append("host name contains a telemetry-like word")
        if any(PATH_HINT.search(p) for p in paths):
            score += W["path_hint"]
            reasons.append("request path looks like a telemetry endpoint (" + ", ".join(sorted(p for p in paths if PATH_HINT.search(p))[:3]) + ")")
        if len(keys) >= 3:
            score += W["keys3"]
            reasons.append(f"payload has telemetry-shaped keys: {', '.join(sorted(keys)[:8])}")
        elif len(keys) == 2:
            score += W["keys2"]
            reasons.append(f"payload has 2 telemetry-shaped keys: {', '.join(sorted(keys))}")
        elif len(keys) == 1:
            score += W["keys1"]
            reasons.append(f"payload has 1 telemetry-shaped key: {', '.join(sorted(keys))}")
        reused = sorted({h for x in http_flows for h in (x.get("id_hashes") or []) if id_flow_counts[h] >= 2})
        if reused:
            score += W["persistent_id"]
            reasons.append(f"a persistent hashed identifier is reused across {max(id_flow_counts[h] for h in reused)} requests")
        ts = sorted(x["ts"] for x in fl if x.get("ts"))
        intervals = [b - a for a, b in zip(ts, ts[1:], strict=False) if b - a > 0.5]
        cv = _cov(intervals) if len(intervals) >= 3 else None
        periodic = cv is not None and cv < 0.35 and statistics.fmean(intervals) >= 1.0
        if periodic:
            score += W["periodic"]
            reasons.append(f"periodic beacon: {len(intervals) + 1} contacts, interval ~{statistics.fmean(intervals):.0f}s (CoV {cv:.2f})")
        posts = [x for x in http_flows if (x.get("method") or "").upper() == "POST"]
        sizes = [float(x.get("req_bytes") or 0) for x in posts]
        if len(posts) >= 3 and statistics.fmean(sizes) > 0 and (_cov(sizes) or 0) < 0.5 and statistics.fmean(sizes) < 65536:
            score += W["uniform_posts"]
            reasons.append(f"{len(posts)} small POSTs of similar size (typical of event batches)")
        score = min(1.0, round(score, 3))

        # ---- label ----------------------------------------------------------
        if is_allowed and not strong:
            label = L_ALLOWED
            if score >= cfg.suspect_threshold:
                reasons.append(f"in allowed_domains: heuristic score {score} ignored (no vendor/blocklist/CNAME match)")
            score_eff = 0.0
        else:
            score_eff = score
            if score >= cfg.telemetry_threshold:
                label = L_TELEMETRY_1P if is_1p else L_TELEMETRY_3P
            elif score >= cfg.suspect_threshold:
                label = L_SUSPECT
            elif is_1p:
                label = L_FIRST_PARTY
            elif opaque_only:
                label = L_OPAQUE
            else:
                label = L_UNKNOWN
        if is_allowed and strong:
            reasons.append("host is in allowed_domains but matches a known telemetry signal: NOT suppressed")
        if opaque_only and label not in (L_TELEMETRY_1P, L_TELEMETRY_3P):
            reasons.append("payload not inspectable (TLS not decrypted / pinned): only SNI + timing available")

        row = {
            "capture_phase": phase, "host": host, "label": label, "score": score_eff, "sdk_id": sdk_id, "category": category,
            "n_flows": n, "req_bytes": sum(int(x.get("req_bytes") or 0) for x in fl),
            "features": {
                "first_party": is_1p, "allowed": is_allowed, "opaque_only": opaque_only, "kinds": dict(Counter(x["kind"] for x in fl)),
                "top_paths": [p for p, _ in paths.most_common(5)], "telemetry_keys": sorted(keys), "reused_id_hashes": reused[:5],
                "interval_cov": None if cv is None else round(cv, 3), "cname_chain": cname_chain, "raw_score": score,
            },
            "reasons": reasons or ["no telemetry signal found"],
        }
        labels.append(row)
        log("DEBUG", f"[{phase}] {host}: score={score} label={label} n={n} :: " + " | ".join(row["reasons"]))
    skipped = sorted(set(notes["dns_skipped_hosts"]))
    notes["dns_skipped_hosts"] = skipped
    if skipped:
        log("WARN", f"CNAME check NOT performed for {len(skipped)} host(s) ({'lookup limit reached' if notes['dns_limit_reached'] else 'DNS unavailable / time budget'}): "
                    + ", ".join(skipped[:5]) + (" ..." if len(skipped) > 5 else ""))
    return labels, dns_rows
