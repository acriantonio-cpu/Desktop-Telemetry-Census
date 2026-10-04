# 02 · Installation (Windows 11 + VS Code)

> **Linux or macOS?** The differences (commands, capture modes, certificate) are in `13-linux-and-macos.md`, with a note on what is verified and what is not.

> **Strong recommendation:** run the tests in a **dedicated Windows 11 virtual machine** (Hyper-V, VirtualBox or VMware)
> with a *clean snapshot*. Reasons: you install a temporary root certificate, you run third-party apps, and you want to be able to
> go back to a known state between one app and the next. Do not use your personal PC with real accounts.

## 1. Prerequisites

| What | How | Check |
|------|-----|-------|
| Python ≥ 3.11 | `winget install Python.Python.3.12` (or python.org, tick *Add to PATH*) | `py --version` |
| Git (optional but useful) | `winget install Git.Git` | `git --version` |
| VS Code | already installed | — |

## 2. Virtual environment and installation

Open the project folder in VS Code → *Terminal → New Terminal* (PowerShell):

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[capture,dev]"
```

* `[capture]` installs **mitmproxy** (only needed to capture traffic).
* `[dev]` installs pytest, ruff, bandit (needed to run the tests).

If PowerShell refuses the activation script ("running scripts is disabled on this system"):

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
```

In VS Code: *Ctrl+Shift+P → Python: Select Interpreter → `.venv`*.

## 3. Environment check

```powershell
claimcheck doctor
claimcheck doctor --online      # also checks internet access
```

It reads: Python, Windows, administrator privileges, CPU, RAM, free disk, mitmdump, git, proxy variables.
`FAIL` = blocking; `WARN` = you can proceed but read the advice; the command also suggests a value for `static.workers`.

## 4. Traffic capture: privileges and certificate

### 4.1 Capture modes

| `capture.mode` | How it works | When |
|----------------|--------------|------|
| `local` (default) | mitmproxy intercepts **per process** (`--mode local:<exe>`) | Windows, apps that ignore the system proxy. **Requires an Administrator terminal** |
| `regular` | HTTP proxy on `127.0.0.1:<listen_port>` | Apps that honour the proxy (or the test canary) |

For `local`: close VS Code and reopen it with *right click → Run as administrator* (or use Windows Terminal
as administrator and activate the venv there). `claimcheck doctor` shows `administrator: OK`.

`app.exe_name` is the process name as shown in *Task Manager → Details* (e.g. `Jan.exe`).
Several processes can be listed, separated by commas (see the mitmproxy documentation on *local capture*).
**Tauri / WebView2 apps:** frontend traffic may leave from `msedgewebview2.exe`, not from the app's exe;
in that case add that process too, knowing that it will also capture other open WebView2 apps (close them).

### 4.2 mitmproxy certificate (needed to read HTTPS)

1. Run `mitmdump` once and stop it with Ctrl+C: it creates `%USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.cer`.
2. Double-click the `.cer` → *Install certificate* → *Local machine* → *Place all certificates in the following store:*
   **Trusted Root Certification Authorities**.
3. **Remove it when testing is over** (`certmgr.msc`/`certlm.msc` → search for "mitmproxy" → delete), or restore the VM snapshot.

Known limits: apps that use their own certificate store (Firefox, many Java/Python apps), or that do
*certificate pinning*, will show `tls_failed`. The tool records them as **opaque** traffic (only the
server name is visible, via SNI): useful information, but the content cannot be read.

## 5. Final check: the canary

Before touching real apps, prove that *tool + your machine* work, using the synthetic app
that contacts no real service. Full procedure in `10-choosing-apps.md` (section *Canary*).

## 6. The project's automated tests

```powershell
pytest -q                                                   # ~400 tests, no network and no mitmproxy needed
$env:CLAIMCHECK_INTEGRATION = "1"; pytest tests\test_integration_mitmproxy.py -s   # requires mitmproxy, ~2-4 min
ruff check src tests ; bandit -r src -c pyproject.toml
```

## 7. Paths: two important warnings

* **Do not put `runs\` inside OneDrive/Dropbox/Google Drive.** SQLite in WAL mode + cloud sync
  can corrupt the database. Use a local folder (e.g. `C:\claimcheck`).
* *Relative* paths in the manifest are resolved against the **folder of the original manifest**
  (not the run folder); when in doubt, use absolute paths.

## 8. Update / uninstall

```powershell
pip install -e ".[capture,dev]" --upgrade      # update dependencies
deactivate ; Remove-Item -Recurse .venv         # remove the environment (runs in runs\ are kept)
```
