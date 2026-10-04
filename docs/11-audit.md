# 11 · Audit report (status as of 20 September 2026)

## What was run
| Check | Outcome |
|-------|---------|
| Unit and system tests (`pytest`, no network) | ~230 tests at the time of this audit, all passing (see the `README`/local CI for the exact count; 403 as of 0.2.1) |
| Integration with a **real mitmproxy** + canary (`CLAIMCHECK_INTEGRATION=1`) | 4 scenarios out of 4 consistent with the ground truth (telemetry, clean, opt-out ignored, opt-out respected) |
| `ruff check src tests` (rules E,F,W,B,S,UP,SIM) | no issues |
| `bandit -r src` | no open issues; the false positives (SQL with placeholders only, `subprocess` with argument lists) are annotated with a justification |
| Coverage | ~89% (uncovered parts: real network/DNS, some Windows branches, `main()`) |

## Problems found and fixed
| # | Problem | Fix | Test |
|---|---------|-----|------|
| 1 | Non-transitive staleness: after new data, `score` was not reported as stale | recursive `is_stale` | `test_stale_detection…` |
| 2 | Relative paths in the manifest resolved against the run folder | base = folder of the original manifest (`run.json`) | `test_relative_paths…` |
| 3 | `git clone` with hostile URLs/refs (option injection) | validation in the manifest + `--` before the URL | `test_hostile_repo_*` |
| 4 | Ingest could read files outside the run folder (other people's runs) | path containment check | `test_ingest_refuses_raw_paths…` |
| 5 | Zip bomb: decompressed bytes inside archives were not counted | total budget applied to archive entries too | `test_zip_bomb…` |
| 6 | Ingest read the whole JSONL into RAM | streaming read, batches of 1000 | `test_ingest_handles_many_lines…` |
| 7 | `classify` also loaded payload samples/features | lightweight `flows_for_classification` query | `test_lean_flow_query…` |
| 8 | Addon errors silently swallowed ("0 records" with no explanation) | `addon_error` record (max 20) + warning at ingest | `test_addon_hooks_swallow…`, `test_addon_error_records…` |
| 9 | SHA-1 for identifier hashes | SHA-256 (12 characters) | `test_addon_*` |
| 10 | `ORDER BY` not validated in `Store.select` | validation regex | `test_select_order_is_validated` |
| 11 | Windows quoting: non-POSIX `shlex` left the quotes in place | outer quotes stripped | `test_split_command…` |

## Provenance of files
During the audit, files not written in the main session appeared in the tree (`canary.py`, `benchmark/canary_*.md`,
`tests/test_addon.py`, `tests/test_signatures.py`, `tests/test_ingest.py`, an inconsistent `truth/canary.yaml`, and changes to `capture.py`).
They were **re-read and validated**: the consistent ones were kept (and integrated into the tests), the inconsistent one was removed.
The duplicate canary in `tools/` was deleted in favour of `python -m claimcheck.canary`.

## Residual risks and known limits
* `local` capture and certificate installation **not tested on Windows** (only simulated + real `regular` mode on Linux).
* TLS pinning, QUIC/UDP and non-HTTP protocols cannot be inspected.
* Hashes of low-entropy identifiers can be guessed with a dictionary: use dummy accounts, do not publish `raw/`.
* The manifest is trusted configuration (it can specify commands): do not run unknown manifests without reading them.
* Classification heuristics can be wrong: verify a sample by hand (see `05`).
* Promise extraction is rule-based; pages rendered by JavaScript are not supported.

## How to re-run the audit
```powershell
pytest -q --cov=claimcheck
$env:CLAIMCHECK_INTEGRATION="1"; pytest tests\test_integration_mitmproxy.py -q
ruff check src tests ; bandit -r src -c pyproject.toml
```


## Addendum 0.2.0 (20 September 2026)
Robustness audit driven by failure modes: see `12-failure-modes.md` (44 problems; 21 reproduced with probes against the 0.1.0 code before the fix, the others inferred from the code; 16 key fixes also verified by mutation: when the defect is reintroduced, the tests fail).
The most serious one: a capture with 0 records produced `NOT_CONTRADICTED`. New tests: `tests/test_v02_verdicts.py`, `test_v02_inputs.py`, `test_v02_runtime.py`.
New command: `claimcheck verify` (integrity of the raw files).
