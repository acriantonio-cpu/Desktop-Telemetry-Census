# 03 · Collecting the input data (before running any command)

> Hash commands, installer formats and paths on Linux/macOS: `13-linux-and-macos.md` §5.

The quality of the result depends on the quality of the **inputs**. This list also serves reproducibility:
a year from now you must be able to say *exactly* what you tested.

## A. App identity (mandatory)

| Data | Where to find it | Manifest field |
|------|------------------|----------------|
| Name and **exact version** | About dialog / download page | `app.name`, `app.version` |
| Downloaded installer + **SHA-256** | `Get-FileHash .\Setup.exe -Algorithm SHA256` | `app.installer_sha256` |
| Download date and URL | write them in `notes.md` (see below) | — |
| Process name | Task Manager → Details | `app.exe_name` |
| Installation folder | E.g. `%LOCALAPPDATA%\Programs\<App>` | `app.install_dir` |
| Stack (electron/tauri/qt/…) | hints: a `resources\app.asar` folder = Electron | `app.stack` |

Always download the **official** installer and keep a copy: if the vendor changes the file, you will be able to prove it.

## B. Source code at the **same tag** as the release (for `open_source`)

The "binary ↔ source" comparison only makes sense if they are the same version.

```powershell
git clone https://github.com/<org>/<repo> C:\claimcheck\src\<app>
cd C:\claimcheck\src\<app> ; git checkout v1.2.3      # the tag of the installed release
```
then `sources.repo_path: C:\claimcheck\src\<app>`. Alternatively `sources.repo_url` + `sources.repo_ref`
(the tool clones with `--depth 1`; `repo_url` must start with `https://`, `http://`, `ssh://` or `git@`).
For **closed-source** apps leave it empty: the `open_source` check will be `INCONCLUSIVE`, which is correct.

## C. The promises: documents to analyse

In `sources.documents` list the pages where the app makes statements: homepage, privacy page, **privacy policy**,
README, telemetry documentation. Valid roles: `privacy_policy`, `readme`, `homepage`, `other`.

* `type: url` (downloaded at run time; a text copy goes to `artifacts/docs/`) or `type: file`.
* The `privacy_policy` role is special: it is used to compare *which providers the app declares* with those *observed*.
* **Pages that require JavaScript** cannot be read by the loader (it does not execute JS): save them as HTML/text
  from the browser and use `type: file`.
* For citability: also save a copy on web.archive.org and write the date and link in `notes.md`.
* With `repo_path` set, the repo's `README` is included automatically.

## D. Test environment

| What | Why |
|------|-----|
| Dedicated Windows 11 VM + `clean-baseline` snapshot | repeatable state; you can remove the certificate by restoring |
| **Dummy account** (new e-mail, no real data) | payloads may contain identifiers |
| VPN/other proxies off, other apps closed | less noise |
| Sleep/hibernation disabled | `powercfg /change standby-timeout-ac 0` during capture |
| Note of the time and of the Windows build | reproducibility |

## E. The usage scenario (`use` phase) — decide it *beforehand*

Write a short, fixed list of actions to perform identically in all comparable apps, e.g.:
1. start the app and wait for it to load; 2. create an item/note; 3. use search; 4. open Settings;
5. check for updates; 6. close. Time it. Without a fixed scenario the results are not comparable.

## F. How telemetry is turned off (`optout` phase)

Look in the app *and* in the documentation for where it is disabled (setting, consent prompt, config file,
environment variable). Take a screenshot of the panel before changing it. If there is no switch,
**that is a finding**: write it down; the `optout` phase is not run.

## G. One run per *configuration*, not one per app

The app's state changes the verdicts. Create separate runs with clear labels:

| Run (`--label`) | App state | Question |
|-----------------|-----------|----------|
| `default, before consent` | first launch, no choice made | "Does it send nothing before consent?" |
| `after opt-in` | telemetry consented to | "What does it send, and who receives it?" |
| `after opt-out` | telemetry revoked | "Does it really stop?" |

For **opt-in** apps (e.g. Jan, GPT4All) this avoids mixing phases with and without consent.

## H. `notes.md` for each run (by hand)

Create `runs\<app>\<run_id>\artifacts\notes.md` with: download URL/date, SHA-256, VM snapshot, `use` scenario
followed, how you enabled/disabled telemetry, anomalies (crashes, pop-ups, restarts), process name.
The file is not read by the tool: it is for you and for reviewers.

## I. Ethics and responsibility (this is not legal advice: check the terms of use)

* Test **software you installed yourself**, on a machine you own, with dummy data.
* Before publishing a `CONTRADICTED` outcome on a real app, **contact the vendor** (responsible disclosure) and give them
  a reasonable time to reply. Present the result as "contradicted by these observations", not as intent.
* Do not publish raw payloads, identifier hashes or IPs; publish tables of hosts, categories and counts.
* Keep `raw/` in a safe place: even redacted, it is still research material.

## Quick checklist

- [ ] version + SHA-256 recorded
- [ ] repo at the right tag (or "closed source" noted)
- [ ] promise documents saved (with date)
- [ ] VM + snapshot + dummy account
- [ ] `use` scenario written
- [ ] opt-out procedure found (or its absence noted)
- [ ] `notes.md` created
