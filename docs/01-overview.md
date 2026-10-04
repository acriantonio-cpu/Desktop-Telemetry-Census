# 01 · Overview: what ClaimCheck is and why it exists

## The problem

Many desktop apps present themselves as "privacy-friendly", "local-first", "open source", "no telemetry".
But **nobody systematically checks** whether their actual behaviour matches these promises.
Existing research on tracking focuses on the web and mobile; for desktop apps, and above all for the
*promise ↔ behaviour* comparison, there is a gap. We call **privacy-washing** the distance
between what an app declares and what it does.

## What the tool does

ClaimCheck compares **three sources of truth** for a single app and flags contradictions:

| Source | What it contains | Phase |
|--------|------------------|-------|
| **Promises** | sentences from the README, homepage, privacy policy ("no telemetry", "your data never leaves your device") | `claims` |
| **Code** | telemetry SDKs present in the installed program and in the source repository | `static` |
| **Behaviour** | real network traffic observed with mitmproxy (idle / in use / after opt-out) | `capture` → `classify` |

Then `score` applies explicit rules (one per type of promise) and produces a **verdict for each one**, with
the evidence attached; `report` generates an HTML + JSON file.

```
 README / policy ──► claims ─┐
 installed app ────► static ─┼──► score ──► report (HTML + JSON)
 source repo ──────► static ─┘      ▲
 network traffic ──► capture ─► classify
```

## Verdicts (always cautious)

| Verdict | Meaning |
|---------|---------|
| `CONTRADICTED` | Observed evidence **contradicts** the promise (e.g. "no telemetry" but traffic to PostHog) |
| `WARNING` | Serious but non-conclusive indication (e.g. SDK in the binary but no traffic seen) |
| `INCONCLUSIVE` | Not enough data to decide (e.g. no capture, no policy) |
| `NOT_CONTRADICTED` | Nothing contrary observed **in the phases covered**. It does *not* mean "proven clean" |

The tool never says "the app is malicious": it says "this sentence is contradicted by these observations".

## Design principles

1. **No data loss.** Result tables are *append-only* (locked down by SQL triggers).
   Re-running a phase creates a new *attempt*; the old one stays. Reports and exports never overwrite.
2. **Restart after a crash.** Traffic is written line by line to `raw/*.jsonl` and imported
   idempotently. If the PC shuts down in the middle of a capture, the data is recovered by the next command.
3. **Transparency.** Every label states its *reasons* in plain text; every verdict lists its evidence;
   `-v`/`-vv` show what is happening on screen; `events` is the persistent journal.
4. **Researcher privacy.** E-mails, UUIDs, tokens and long numbers are redacted in payload samples;
   persistent identifiers are stored only as hashes.
5. **Bounded resource usage.** Chunked scans, size/time budgets, disk/RAM guards
   during capture (see `06-hardware-resources.md`).
6. **Validated against ground truth.** A synthetic app (the *canary*) with known behaviour checks the tool
   itself before it is used on real apps (see `10-choosing-apps.md`).

## Structure of a "run"

```
runs/<app>/<run_id>/
  manifest.yaml     frozen copy of the manifest used
  run.json          metadata (label, original manifest folder)
  store.sqlite      database (append-only)
  raw/              raw JSONL traffic (source of truth, do not delete)
  logs/             claimcheck.log, mitmdump-*.log
  artifacts/        downloaded documents (docs/), cloned repo, imported files
  reports/          report_001.html/.json, report_002... (never overwritten)
```

Each app has several runs (e.g. one per configuration: "default", "after opt-in"). `runs/<app>/LATEST` points to the latest one.

## Where to go next

* Install: `02-installation.md`
* What to collect before starting: `03-input-data-collection.md`
* Run a complete test: `04-step-by-step-run.md`
* Understand the results: `05-interpreting-results.md`
