# Changelog

## Unreleased
Documentation only (no functional code change).
- All documents in `docs/` translated from Italian into English and renamed with English file names (e.g. `01-panoramica.md` → `01-overview.md`); references in code, tests and README updated.

## 0.2.1 - 2026-09-20
Documentation-only release (no functional code change).
- New `docs/13-linux-and-macos.md`: differences from Windows, capture modes, certificate install/removal, installer formats, bash canary flow, pitfalls, and a validation checklist for a new OS. Every step is marked verified (Linux sandbox) or unverified (macOS, Linux `local` mode).
- Pointers added in README and docs 02, 03, 07, 10.
- The source zip no longer contains a stray `.coverage` file.

## 0.2.0 - 2026-09-20
Robustness release. Full list, tests and residual risks: `docs/12-failure-modes.md`.

### Fixed (verdict validity)
- An empty (0 records), opaque (TLS pinning / CA not trusted) or unclassified capture no longer yields `NOT_CONTRADICTED`.
- Incomplete static scans (skipped files, read errors, compressed containers/installers) no longer clear `open_source`.
- Claim extraction: curly quotes / non-breaking hyphens, very long sentences, negations and FAQ questions.
- Privacy-policy disclosure: negated mentions, empty/bot-check/JS policies, generic telemetry admissions.
- Stale results after `exclude`/`include` or manifest edits; source repo version mismatch is reported.
- Shared cloud domains (amazonaws.com, workers.dev...) are no longer treated as first party.

### Fixed (safety & robustness)
- Redaction of request paths, key names, user names in paths, IPs, keys, JWTs; bounded decompression (gzip bombs).
- Capture: silent addon = error, failed ingest = `partial`, suspend/clock-jump detection, shielded cleanup, mitmdump lookup next to the interpreter.
- Ingest/import: malformed JSONL and HAR records, oversized lines, NaN/inf values.
- Runs: recycled-PID locks, foreign-host locks, path traversal in `--app/--run/LATEST`, atomic run creation, UTC ids.
- SQL sandbox (`sql`, `show --where`): SELECT-only authorizer and 20 s limit; `synchronous=FULL`.
- Manifest: numeric ranges, domain normalisation, UTF-16/BOM, safe templates, safe slugs, http(s)-only documents.
- git clone never prompts, is atomic and records the scanned commit; DNS circuit breaker; atomic blocklist download.

### Added
- `claimcheck verify` (raw-file SHA-256 integrity), data-quality banner in the HTML/JSON report, 7 telemetry vendors.

### Changed
- `req_bytes` is the on-the-wire size when the body could not be fully decoded.
- Run ids are UTC (`YYYYMMDD-HHMMSS[-NNN]`).

## 0.1.0
Initial research prototype.
