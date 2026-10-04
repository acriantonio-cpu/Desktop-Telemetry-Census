# 04 · Step-by-step run (a complete run)

All commands are run from the project folder, with the venv active. Options common to almost all commands:
`--runs-root <folder>` (default `runs`), `--app <slug>`, `--run <id|latest>`, `-v` / `-vv` / `--debug`.
With a single app and a single run they are not needed.

## Step 0 — once only

```powershell
claimcheck doctor
claimcheck fetch-lists        # optional: downloads the Disconnect list (improves classification)
```

## Step 1 — manifest

```powershell
claimcheck candidates                    # list of candidate apps
claimcheck candidates --make jan         # writes a pre-filled apps\jan.yaml
# or, for your own app:
claimcheck new "App Name"                # writes apps\app-name.yaml
```
Open the file and complete the `TODO` lines (version, `install_dir`, `repo_path`, `exe_name`). See `03-input-data-collection.md`.

## Step 2 — create the run

```powershell
claimcheck init apps\jan.yaml --label "default, before consent"
```
Creates `runs\jan\<date-time>\` with a **frozen copy** of the manifest. From here on that copy is used
(if you need to fix something, edit `runs\jan\<id>\manifest.yaml`). It never touches existing runs.

## Step 3 — automatic phases (no app and no capture network needed)

```powershell
claimcheck claims        # reads the documents and extracts the promises
claimcheck static        # looks for telemetry SDKs in the installed app and in the repo
```
`static --side binary|repo|both` limits the side that is scanned. If a document fails to load, `claims` says so and continues
with the others; if none can be loaded, it fails with a hint.

## Step 4 — capture, `idle` phase (Administrator if `mode: local`)

```powershell
claimcheck capture --phase idle                  # duration from the manifest (idle_minutes, default 5)
claimcheck capture --phase idle --minutes 10
claimcheck capture --phase idle --launch         # starts the app by itself (needs app.exe_path)
```
What happens: resource checks → `mitmdump` starts with the addon → one status line every 5 s
(`records`, size, disk, RAM) → at the end the JSONL is imported into the database.
**Start the app and do not touch it**: we measure what it sends on its own. `Ctrl+C` stops gracefully (the data is kept).

## Step 5 — `use` phase (fixed scenario)

```powershell
claimcheck capture --phase use        # use_minutes=0: runs until you press Ctrl+C
```
Perform the scenario you wrote beforehand. Press `Ctrl+C` at the end of the scenario: the phase is recorded as `done`.

## Step 6 — `optout` phase (optional)

Disable telemetry in the app *before* starting:
```powershell
claimcheck capture --phase optout
```
Enables the `optout_effective` check (does telemetry really stop?).

## Step 7 — analysis

```powershell
claimcheck classify      # labels every host per phase, with the reasons
claimcheck score         # verdict for every promise
claimcheck report --open # writes reports\report_001.html/.json and opens the browser
```

Shortcut: `claimcheck resume` runs all automatic phases that are missing, failed or **stale**
(new capture data → redo classify/score/report). `claimcheck resume --with-capture` also starts the missing captures.
`claimcheck run apps\x.yaml` = init + automatic phases.

## I already have traffic captured elsewhere

```powershell
claimcheck import-flows capture.har --phase use --format har     # HAR from browser/Fiddler/Charles
claimcheck import-flows capture.jsonl --phase use --format jsonl
```
The original is copied to `artifacts\imports\` and is never modified.

## Checking the status at any time

```powershell
claimcheck status            # phases, attempts, rows stored, next steps
claimcheck runs              # all runs (* = latest)
claimcheck --help
```
To go back to an earlier run: `claimcheck status --run <id>`; runs are never mixed.

## Repeating or discarding a capture

* Repeating a phase = running the command again: a **new attempt** is created; captures are *added up*, analyses use the latest one.
* Noisy capture (e.g. you touched the app during `idle`): `claimcheck exclude <attempt_id>` (see IDs with `show attempts`),
  then `claimcheck resume`. Reversible with `include`. No data is deleted.

## If something is interrupted

Run the same command again, or `claimcheck status`: raw data not yet imported is recovered automatically
(see `07-debugging-and-troubleshooting.md`, section *Crashes*).

## Exporting

```powershell
claimcheck export --out C:\claimcheck\jan-default.zip
```
Zip with a consistent snapshot of the database (even if there were recent writes). Never overwrites.

## Compact example (app with opt-in telemetry)

```powershell
claimcheck candidates --make jan ; notepad apps\jan.yaml
claimcheck init apps\jan.yaml --label "default, before consent"
claimcheck claims ; claimcheck static
claimcheck capture --phase idle --minutes 5      # do NOT click the consent prompt
claimcheck capture --phase use                   # scenario, Ctrl+C
claimcheck resume ; claimcheck report --open
# then a NEW run: claimcheck init apps\jan.yaml --label "after opt-in"  ...
```
