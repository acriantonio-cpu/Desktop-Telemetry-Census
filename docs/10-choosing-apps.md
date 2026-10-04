# 10 · Which apps to test and how

The catalogue (`claimcheck candidates`) is a **starting point**: it describes public promises to *verify*, not accusations.
The `verified_claim` entries were checked against the stated source (`verify_at`) in September 2026; the `to_verify` ones were not:
read them yourself before testing. Sources change: check again.

## Roles in the experimental design

| Role | Purpose |
|------|---------|
| `synthetic_control` | fake app with known behaviour: **validates the tool** |
| `control_negative` | documented telemetry: the tool must detect it (recall) |
| `control_positive` | build/app documented as having no telemetry or opt-in only: the tool must stay silent (false positives) |
| `claim_test` | public promises to compare with behaviour (the research question) |

## Tier A — pilot (7)

| App | Role | Why | What to observe |
|-----|------|-----|-----------------|
| **canary** | synthetic | ground truth | all 4 behaviours |
| **VSCodium** | control_positive | same code as VS Code without Microsoft telemetry | no MS telemetry endpoints; keep `open-vsx.org` in `allowed_domains` |
| **VS Code** | control_negative | documented telemetry that can be disabled (`telemetry.telemetryLevel`) | detection + `optout` phase |
| **Jan** | claim_test | local AI, "100% offline", opt-in analytics (PostHog) | nothing before consent; PostHog only after opt-in; nothing after opt-out; no chat content |
| **GPT4All** | claim_test | native Qt app (not Electron), opt-in analytics at first launch | first-launch prompt, both ways |
| **Zed** | claim_test | disclosed telemetry, relayed through the vendor's servers | detection of **first-party** telemetry; diagnostics/metrics switches |
| **Syncthing** | control_positive | opt-in usage reporting + lots of P2P traffic | hard case for false positives |

Recommended order: canary → VSCodium/VS Code (pair) → Syncthing → Jan → GPT4All → Zed.

## Tier B — extension (12)
Joplin, Logseq, AppFlowy, Obsidian (closed source: behaviour only), Element Desktop, Signal Desktop, Bitwarden Desktop,
KeePassXC, Notesnook, Anytype, Cherry Studio, Cryptomator. They diversify the stack (Java, Qt, Flutter) and the category.
`claimcheck candidates --tier B`.

## How to choose other apps
1. An **explicit privacy promise** on the official page (note the URL and date).
2. Installable on Windows without a real account; version and installer downloadable, with a hash.
3. Preferably open source (for the binary ↔ source comparison) — but include some closed-source ones.
4. Vary the stack and the category (notes, local AI, editors, messaging, password managers, sync).
5. Search for "local-first", "no telemetry", "privacy-first" in READMEs and in free-software lists; always check the sources.
6. Exclude apps that require a paid account or whose terms forbid traffic analysis.

## How to test each app
`claimcheck candidates --make <slug>` → complete the manifest → follow `04-step-by-step-run.md`, one run per configuration (03 §G).

## Canary (validation of the tool)

> On Linux/macOS use the bash commands in `13-linux-and-macos.md` §6 (verified on Linux); the blocks below are PowerShell.

Done **before** anything else. The canary only contacts hosts that mitmproxy answers locally (`capture.canary_suffix`): no real service.

```powershell
claimcheck candidates --make canary          # writes apps\canary.yaml (mode: regular, documents in benchmark\)
claimcheck init apps\canary.yaml --label "canary telemetry"
claimcheck claims
# terminal 1:
claimcheck capture --phase idle --minutes 3
# terminal 2 (right after the proxy has started, same port 8080):
python -m claimcheck.canary --behaviour telemetry --proxy http://127.0.0.1:8080 --minutes 2.5 --interval 5
claimcheck classify ; claimcheck score
claimcheck benchmark benchmark\truth\canary-telemetry.yaml
```
Behaviours: `clean`, `telemetry`, `optout-respected`, `optout-ignored`. For the two opt-out ones: `idle` phase without the flag file,
then create the file (`--flag-file optout.flag`) and run the `optout` phase with the same command. Ground truth in `benchmark/truth/canary-*.yaml`.
If `benchmark` reports a `MISMATCH`, **do not use the tool on real apps** until you understand why (`show labels`, `show verdicts`).
