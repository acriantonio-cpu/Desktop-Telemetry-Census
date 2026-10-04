# 09 · Methodology, validity and limits

## Research question
To what extent are the privacy statements of desktop apps (privacy-friendly, local-first, open source, no telemetry)
consistent with their observable behaviour and with their published code?

## Design
1. **Promise extraction** (explicit, reproducible rules, with qualifiers).
2. **Static evidence** (SDKs in the binary vs in the repo at the same version).
3. **Dynamic evidence** (traffic under three conditions: idle, use with a fixed scenario, after opt-out).
4. Declared **comparison rules** (one per type of promise) with four-valued verdicts.
5. **Validation of the tool** against ground truth: canary (4 behaviours) + real positive/negative controls.

## Measures
Precision and recall against ground truth (`claimcheck benchmark`), at verdict level (positive = `CONTRADICTED`) and at host level
(positive = telemetry). On the canary the target is 100% and the integration test checks it. On real apps the measures depend
on manual verification: a sample of labelled hosts must be checked by hand and counted.

## Threats to validity
| Type | Threat | Mitigation |
|------|--------|------------|
| Construct | "telemetry" is a fuzzy concept; heuristics may confuse updates or sync | explicit reasons per host, `allowed_domains`, manual verification, cautious terminology |
| Internal | limited coverage of actions during capture | fixed and declared `use` scenario; repeatable captures that can be added up |
| Internal | app state (consent) changing the traffic | one run per configuration |
| External | few apps, all on Windows | tiered catalogue (A pilot, B extension), different stacks (Electron, Qt, Tauri, Rust, Go, Java) |
| Tool | TLS pinning, QUIC/UDP and non-HTTP protocols cannot be inspected | recorded as opaque; documented; no `NOT_CONTRADICTED` presented as proof |
| Tool | incomplete signatures and blocklists; obfuscated code | behavioural heuristics; scan coverage in the report |
| Temporal | DNS (CNAME) is resolved at analysis time | declared in the report |

## What the tool does **not** claim
* It does not prove the absence of telemetry; it does not judge intent; it does not assess legal compliance (GDPR or other).
* It does not inspect pinned encrypted content or non-HTTP channels.
* Promises are extracted with rules: unusual phrasings may be missed, and marketing prose may be over-counted.

## Reproducibility
Every run keeps: a copy of the manifest and its hash, the tool version, the parameters of every attempt, raw files with sha256,
the event journal. Record by hand the installer version + SHA-256 and the VM snapshot (see 03).

## Validation status (honesty)
* Verified with automated tests on Linux: logic, database, scans, classification, verdicts, report, recovery after a crash.
* Verified with a real mitmproxy on Linux in `regular` mode with the canary.
* **Not yet verified on Windows:** `local` (per-process) capture and certificate installation. Run the canary on your VM first.

## What `INCONCLUSIVE` means (0.2.0)
A `NOT_CONTRADICTED` verdict is issued only if traffic was actually observed *and inspected* and the static scan is complete. An empty capture, non-inspectable TLS, unclassified traffic, an unusable policy or an incomplete scan yield `INCONCLUSIVE` or `WARNING`, with the reasons listed at the top of the report ("Data-quality warnings").

## Ethics
See `03-input-data-collection.md` §I: dummy data, responsible disclosure before publication, no public raw data.
