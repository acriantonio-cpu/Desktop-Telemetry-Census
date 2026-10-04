# 05 · Interpreting the results

## The HTML report

Sections, in order: **Verdicts** (with expandable evidence) → **Observed traffic** (label per host and phase, with the
reasons) → **Static findings** → **Extracted promises** → **History** of attempts → **How to read the report**
(limits). The JSON contains the same data for further analysis. Every value coming from outside is
escaped and the page has a restrictive CSP: opening a report about a hostile app executes nothing.

## Verdicts by type of promise

| Promise (`claim`) | `CONTRADICTED` when… | `WARNING` when… |
|-------------------|----------------------|-----------------|
| `no_telemetry` | traffic classified as telemetry (3rd party: high severity; 1st party: medium) | SDK in the binary with no traffic observed, or "suspect" hosts |
| `no_third_party_sharing` | traffic to third-party telemetry/trackers | — |
| `local_first` | session replay, or large uploads to unknown hosts | telemetry present (check the content) |
| `privacy_friendly` | telemetry not disclosed in the loaded privacy policy | no policy loaded, or telemetry disclosed but present |
| `open_source` | SDKs in the **binary** missing from the **repo** (same version) | weak indication (string only) |

Additional checks without a promise: `optout_effective` (telemetry still present after opt-out) and
`policy_disclosure` (observed providers not mentioned in the policy).

If a sentence has **qualifiers** ("unless you opt in", "by default"…), confidence drops and the verdict reminds you to
check by hand: always read the original sentence.

## Traffic labels

| Label | Meaning |
|-------|---------|
| `telemetry_third_party` | known vendor (e.g. PostHog, Sentry) or strong resemblance to telemetry sent to a third party |
| `telemetry_first_party` | telemetry to the vendor's own domains (incl. CNAME cloaking towards a known vendor) |
| `suspect` | score between `suspect_threshold` (0.4) and `telemetry_threshold` (0.7) |
| `first_party` / `allowed` | vendor domain / declared by you as expected (updates, model downloads) |
| `opaque_unknown` | encrypted connection that cannot be inspected (pinning): server name only |
| `unknown` | cannot be classified: look at it by hand |

The score adds up weighted indicators: vendor domain 0.90; CNAME to a vendor 0.85; blocklist 0.60; hint words in the host
or path; payload shape (keys such as `event`, `distinct_id`); reused persistent identifier;
periodic sending; small, uniform POSTs. The **reasons** are listed for every host.

## How to verify by hand (mandatory before citing a result)

```powershell
claimcheck show labels --where "label like 'telemetry%'"
claimcheck show flows --where "host like '%posthog%'" --all-columns --limit 5
claimcheck sql "SELECT capture_phase, host, COUNT(*) n FROM flows GROUP BY 1,2 ORDER BY n DESC"
```
Compare the (redacted) payload and keys with the vendor's documentation; check that the host is not an expected
service (updates, CDN). If it is, add it to `allowed_domains` and run `claimcheck resume`.

## Typical false positives

* Periodic update checks or sync polling (regular, hence "periodic").
* Crash-report services triggered only on errors, but disclosed by the vendor.
* Peer-to-peer traffic (e.g. Syncthing): many unknown hosts, not telemetry.

## Typical false negatives

* Telemetry over channels that are not seen (UDP/QUIC, non-HTTP protocols), or triggered by events you did not cause.
* TLS pinning: the content cannot be read.
* Renamed/obfuscated or natively compiled SDKs: the static scan relies on signatures.

`NOT_CONTRADICTED` = "nothing contrary in the phases covered", **not** a certification.

## What to report in a paper

Report: version, configuration (run), phase durations, scenario, number of records, host/category tables,
verdict with the original sentence and its date, limits (the *How to read the report* section), and the outcome of the canary tests.
