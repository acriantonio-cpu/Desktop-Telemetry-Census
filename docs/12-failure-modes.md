# 12 · Failure modes, fixes and residual risks (release 0.2.0)

This document lists the ways in which ClaimCheck 0.1.0 could **give a wrong result or fail to notice a
problem**, how they were fixed in 0.2.0 and which tests guard them (`tests/test_v02_*.py`; the ID `FMxx` appears in the
test names). "Demonstrated" = reproduced with a probe against the 0.1.0 code *before* the fix (21 cases); the others were inferred from the code and are covered by tests. Mutations (reintroducing the defect) were tried on 16 fixes and caught by the tests in every case (two tests, FM01 and FM18, were strengthened because at first they did not catch them).

## A. Verdict validity (the most serious: a false "clean")
| ID | Problem in 0.1.0 | Fix in 0.2.0 |
|----|------------------|--------------|
| FM01 | A capture with **0 records** (CA not trusted, wrong `exe_name`, proxy not used) produced `NOT_CONTRADICTED` (demonstrated) | `Facts.has_traffic()`: without records the verdict is `INCONCLUSIVE`; data-quality warning |
| FM02 | Only opaque traffic (pinning / CA not trusted) or never classified → `NOT_CONTRADICTED` | `_opacity_gate`: `INCONCLUSIVE` if nothing was inspected, `WARNING` if there are opaque third-party hosts |
| FM03 | Typographic apostrophes/hyphens (`don’t`, `privacy‑friendly`) → claims not found (demonstrated); UTF-8 pages without a charset decoded as Latin-1 (inferred from the code) | `fold_typography` at match time; UTF-8 decoding before the fallback |
| FM04 | Legal sentences > 400 characters truncated *before* matching (demonstrated) | match on the whole sentence (windows for text without punctuation); snippet centred on the match |
| FM05 | "not open source", "Is it open source?" extracted as positive claims (demonstrated) | negation guard + questions are not promises |
| FM06 | "we do **not** use Google Analytics" counted as a *disclosure* (demonstrated) | negated mentions ignored (with an exception for contrastive clauses: "…but we use Sentry") |
| FM07 | Empty policy / JS page / bot check (Cloudflare) = "policy loaded" → every vendor "undisclosed" | `is_usable_policy` (≥ 400 characters, no anti-bot wall); otherwise `INCONCLUSIVE` |
| FM08 | First-party telemetry without a vendor always "undisclosed" | *generic* disclosure (`__generic_telemetry__`); without it, `WARNING` (manual check) instead of `CONTRADICTED` |
| FM09 | Incomplete static scan (files too large, budget, errors) → `NOT_CONTRADICTED` on `open_source` | `Facts.static_gaps()` → `INCONCLUSIVE` |
| FM10 | After `exclude`/`include` or a manifest edit, results stayed "fresh" (demonstrated); repo at the wrong version not reported | staleness on the **set** of inputs + manifest hash; `repo_info` records commit/tag and warns if it does not match `app.version` |
| FM11 | `amazonaws.com`, `workers.dev`… as registrable domain → the whole cloud counted as "first party" (demonstrated) | for shared cloud domains the registrable domain is the host itself |

## B. Privacy of the tool
| ID | Problem | Fix |
|----|---------|-----|
| FM12 | `path` and JSON **key names** not redacted; Windows user names, IPs, MACs, AWS/GitHub keys, JWTs, Bearer tokens remained in the samples (demonstrated) | extended redaction, applied to paths, keys, user agents; `addon.redact` == `util.redact_text` (tested) |
| FM18 | A hostile app could send a gzip bomb (194 KB → 200 MB) and exhaust mitmproxy's RAM; `req_bytes` = 0 if decoding failed | streaming decompression capped at 256 KB; if incomplete, the on-the-wire size is recorded |
| FM25 | Export without a warning, following symlinks; no integrity check of raw files | `export` skips symlinks and itself, and warns; new command `claimcheck verify` (SHA-256 of the raw files) |
| —   | Run folders world-readable (POSIX) | `0o700` |

## C. Capture
| ID | Problem | Fix |
|----|---------|-----|
| FM14 | Ingest failing at the end of capture → status `DONE` with "0 records" | status `PARTIAL` + note; `claimcheck ingest` recovers under the same attempt |
| FM15 | PC suspend / clock jump: "idle" window not continuous but `DONE` | monotonic clock + jump detection → `PARTIAL` |
| FM16 | A second Ctrl+C during cleanup left `mitmdump` orphaned; a failed `Popen` leaked the handle | cleanup shielded from SIGINT; handle closed |
| FM19 | `mitmdump` not found if the venv is not activated | lookup next to the interpreter (`Scripts/`, `bin/`) |
| FM20 | WebView2/Tauri apps: web traffic goes through `msedgewebview2.exe`, not seen by `local:<exe>` | warning in the manifest; use `exe_name: "App.exe,msedgewebview2.exe"` |
| FM21 | Addon that does not start → "successful" capture with 0 records | explicit error after 25 s without the `meta` line |

## D. Ingest, import, configuration, resources
| ID | Problem | Fix |
|----|---------|-----|
| FM22 | JSONL with malformed fields (`ts:"abc"`, `host:123`, `NaN`) crashed the ingest (demonstrated) | every field coerced; unrecoverable records counted as "bad" |
| FM23 | HAR with non-dict entries crashed; huge HAR read into RAM; base64 bodies/`params` ignored | validation, 300 MB cap, base64 and form params |
| FM24 | A giant JSONL line ended up in RAM | capped read (4 MB) and discard |
| FM26 | A lock with a **recycled PID** blocked the run forever (demonstrated); a lock from another host silently recycled (demonstrated) | process `create_time` in the lock; a lock from another host is never recycled without `CLAIMCHECK_FORCE_UNLOCK=1` |
| FM27 | `--run ../x` escaped the runs folder; tampered `LATEST` (demonstrated) | validation of names and of `LATEST` |
| FM28 | `LATEST` updated before init finished; ids in local time (DST); manifest read twice | `LATEST` last, cleanup on error, UTC ids with a 3-digit suffix, manifest read once |
| FM29 | `claimcheck sql` without a time limit (demonstrated) | SQLite authorizer (SELECT only) + 20 s timeout |
| FM30 | DB errors reported as "unexpected"; print crash on a cp1252 console (demonstrated) | guided messages; `stdout/stderr` with `errors="replace"`; silent `BrokenPipe` |
| —   | `synchronous=NORMAL`; attempt sequence not atomic across processes | `FULL`; `BEGIN IMMEDIATE` |
| FM32 | `.inf`, negative values, `heartbeat_seconds: 0` accepted (demonstrated) | ranges validated |
| FM33 | `first_party_domains: ["https://Jan.AI/"]`, `null`, `*.x.com` accepted and never matching (demonstrated) | normalised or rejected |
| FM34 | `claimcheck new 'My "App"'` produced broken YAML (demonstrated) | values serialised as JSON strings (valid YAML) |
| FM35 | UTF-16 manifest (PowerShell `>`) → traceback (demonstrated) | BOM/UTF-16 handled; clean error |
| FM36 | Slugs `CON`/`NUL`/`COM1` (cannot be created on Windows), non-Latin names all becoming `app`, very long names (demonstrated) | safe and stable slugs |
| FM37 | Signature files with wrong types (a string instead of a list → iterated character by character) | strict validation; warning if an extra signature replaces a vendor |
| FM38 | Disconnect list: string values (`"dnt":"eff"`) iterated by character → domains `e`,`f`,`r`… (demonstrated); non-atomic download | type-checked parsing; provenance (SHA-256) recorded; atomic write |
| FM45 | Blocklists from the user folder included without a trace | names and SHA-256 in the `classify` summary |

## E. Static scanner, network
| ID | Problem | Fix |
|----|---------|-----|
| FM39 | An anomalous `asar` node aborted the whole `static` phase (demonstrated) | every file is isolated; errors go to the coverage |
| FM40 | `.7z`, `.msi`, `.tar.gz`, `Setup*.exe` installers "scanned" with nothing to find | listed as **not inspectable**; they make the scan incomplete (FM09) |
| FM41 | `count.ly` matched inside `account.ly` | word boundary for domain-type needles |
| FM42 | `git clone` stuck on a credentials prompt (up to 15 min); partial clone reused | `GIT_TERMINAL_PROMPT=0`, clone into a temporary folder + atomic rename, `ext`/`file` protocols disabled |
| FM43 | 200 sequential 3-second DNS lookups even when offline | circuit breaker after 5 consecutive failures + 90 s budget; unchecked hosts are declared |
| FM44 | `http_fetch` without a scheme check and without an overall time limit | `http(s)` only, 60 s cap, truncation reported |

Seven vendors added to the signatures: Clarity, Cloudflare Web Analytics, Umami, Fathom, Pendo, LaunchDarkly, Honeycomb.

## Residual risks (not solved, worth knowing)
* **Windows not verified**: `local` capture, `CTRL_BREAK_EVENT`, process `create_time`, cp1252 console were tested only on Linux (cp1252 simulated). Run the canary on your VM.
* **WebSocket, QUIC/HTTP3, gRPC over non-HTTP/1-2 channels**: not inspected; the addon does not record WebSocket messages.
* **Qualified claims** ("no telemetry *unless* you consent"): the verdict stays `CONTRADICTED` with a note; the tool does not know which consent state the capture was taken in.
* **Opt-out phase**: start-up traffic preceding the deactivation counts as "after the opt-out". Start the capture with the app already configured.
* **Linguistic heuristics** (negations, generic disclosure, "usable" policy): they reduce wrong results but are not infallible; always read the source sentence.
* **Theoretical lock race**: two processes claiming the same stale lock *at the same instant* could both proceed. Tried with 10 real processes: **not reproduced**; left unchanged.
* Locks in the 0.1.0 format (without `create_time`) are still interpreted with the old criterion (live PID = busy).
