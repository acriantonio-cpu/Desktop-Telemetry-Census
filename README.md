# ClaimCheck

Detect **privacy-washing** in desktop apps: compare what an app *claims* (README, homepage, privacy policy)
with what it *contains* (telemetry SDKs in the installed binary vs. the published source) and what it *does*
(network traffic observed with mitmproxy: idle, in use, after opt-out).

Each claim gets a cautious verdict — `CONTRADICTED`, `WARNING`, `INCONCLUSIVE`, `NOT_CONTRADICTED` — with the evidence
attached, in a self-contained HTML + JSON report. The tool never claims to *prove* an app is clean.

> Status: research prototype (v0.2.1). Validated on Linux with a synthetic app of known behaviour (the *canary*).
> Windows per-process capture is **not yet verified** — run the canary on your machine first (`docs/10-choosing-apps.md`).

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate          # Windows: .\.venv\Scripts\Activate.ps1
pip install -e ".[capture,dev]"
claimcheck doctor
claimcheck candidates                                  # built-in catalogue of apps to test
claimcheck candidates --make jan                       # ready-made manifest
claimcheck init apps/jan.yaml --label "default"
claimcheck claims && claimcheck static
claimcheck capture --phase idle                        # admin terminal for capture.mode=local on Windows
claimcheck resume && claimcheck report --open
```

## Design guarantees

* **No data loss:** result tables are append-only (enforced by SQL triggers); re-running a phase adds an attempt; reports and exports never overwrite.
* **Crash-resumable:** raw traffic is journaled line by line and re-ingested idempotently.
* **Transparent:** every label lists its reasons; `-v/-vv/--debug`, a persistent event journal, read-only `show`/`sql`.
* **Never a false "clean":** an empty, opaque or incomplete observation yields `INCONCLUSIVE`, and the report opens with data-quality warnings.
* **Bounded resources:** streaming scans, size/time budgets, disk/RAM guards during capture.
* **Validated against ground truth:** `claimcheck benchmark` + the canary app (`python -m claimcheck.canary`).

## Documentation

The guides were written for Windows 11 first; `docs/13-linux-and-macos.md` covers the differences on Linux and macOS.

| File | Content |
|------|---------|
| `docs/01-overview.md` | what/why, architecture |
| `docs/02-installation.md` | Windows 11 + VS Code setup, mitmproxy certificate |
| `docs/03-input-data-collection.md` | what to collect before testing, ethics |
| `docs/04-step-by-step-run.md` | full step-by-step run |
| `docs/05-interpreting-results.md` | reading verdicts/labels, manual verification |
| `docs/06-hardware-resources.md` | CPU/RAM/disk management |
| `docs/07-debugging-and-troubleshooting.md` | debugging, crash recovery |
| `docs/08-configuration-reference.md` | manifest, commands, data model |
| `docs/09-methodology-and-limits.md` | method, validity, limits |
| `docs/10-choosing-apps.md` | candidate apps + canary |
| `docs/11-audit.md` | audit report |
| `docs/12-failure-modes.md` | failure modes fixed in 0.2.0, tests, residual risks |
| `docs/13-linux-and-macos.md` | Linux and macOS: what differs from Windows, with a verified / unverified marker on every step |

## Tests

```bash
pytest -q                                              # no network, no mitmproxy needed
CLAIMCHECK_INTEGRATION=1 pytest tests/test_integration_mitmproxy.py -s   # real mitmproxy + canary
```

## Responsible use

Test software you installed yourself, on your own machine, with dummy data. Contact vendors before publishing
findings. Results say "contradicted by these observations", not "malicious". Not legal advice.

## License

MIT (see `LICENSE`). Third-party blocklists are not bundled; check their licences before redistributing.
