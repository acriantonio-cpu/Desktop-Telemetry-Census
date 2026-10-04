# 13 · Linux and macOS

Documents 02-10 are written for **Windows 11** (PowerShell, `certlm.msc`, `local` capture mode). This document
explains what changes on Linux and macOS. It does not replace the others: the logic (manifest, phases, verdicts) is identical.

## 0. Verification status: read this first

| Marker | Meaning |
|--------|---------|
| ✅ **verified** | actually tested, on Ubuntu 24.04, Python 3.12.3, mitmproxy 12.2.3, a virtual machine with 1 vCPU |
| ⚠️ **to verify** | standard command or behaviour documented elsewhere, **not tested** here: try it yourself and fix this file |

What is verified on Linux:
* ✅ installation, `claimcheck doctor`, the whole test suite (403 tests) and the 4 integration tests with a real mitmproxy;
* ✅ the canary flow (section 6) up to `benchmark` with the outcome "all expectations met" (precision and recall 1.0);
* ✅ installation and **removal** of the certificate in the system trust store (Debian/Ubuntu) and in an NSS database;
* ✅ `regular`-mode capture of an HTTPS request made with `curl` that trusts only the system trust store;
* ✅ `local` mode on Linux requires the `sudo` program (without it, mitmproxy stops with "Failed to run sudo").

**Nothing has been tested on macOS.** Every macOS command below is ⚠️. The full `local` mode on Linux has not
been tested either (the test machine does not allow it: see 3.3).

## 1. What changes compared to Windows

| Topic | Windows (docs 02-04) | Linux | macOS |
|-------|----------------------|-------|-------|
| Activate the venv | `.\.venv\Scripts\Activate.ps1` | `. .venv/bin/activate` | `. .venv/bin/activate` |
| Installer hash | `Get-FileHash f -Algorithm SHA256` | `sha256sum f` ✅ | `shasum -a 256 f` ⚠️ |
| Recommended capture mode | `local` (per process) | **`regular`** (HTTP proxy) ✅ | **`regular`** ⚠️ |
| Privileges for `local` | Administrator terminal | `sudo` present and privileges (3.3) | system approval (3.4) ⚠️ |
| Certificate | "Trusted Root Certification Authorities" store | trust store + NSS (section 4) ✅ | System keychain ⚠️ |
| Prevent sleep | `powercfg /change standby-timeout-ac 0` | `systemd-inhibit` (section 6) | `caffeinate` ⚠️ |
| Paths in the manifest | `%LOCALAPPDATA%\Programs\App` | `~/apps/App` or `$HOME/...` ✅ | `/Applications/App.app` ⚠️ |
| Process name | Task Manager (`App.exe`) | `ps -eo comm` / `pgrep -a` | `ps -axo comm` ⚠️ |

In the manifest, `~` and `$VARIABLE` work ✅ (tested); the Windows `%VARIABLE%` form is **not** expanded on Linux/macOS ✅
(tested: it stays literal, and the path would not exist). Use `~` or `$HOME`.

## 2. Installation

Requirements: Python ≥ 3.11, git (optional but useful) and, on Linux, `sudo` if you will use `local` mode.

Linux (Debian/Ubuntu) ✅:
```bash
sudo apt install python3-venv python3-pip git
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[capture,dev]"          # or: pip install claimcheck-0.2.1-py3-none-any.whl
claimcheck doctor
```

macOS ⚠️: the system Python may be older than 3.11 (`python3 --version`). With Homebrew:
`brew install python@3.12 git`, then the same commands as above with `python3.12 -m venv .venv`.

`claimcheck doctor` on Linux/macOS: the "administrator" line tells whether you are root (uid 0). It is **not needed** for `regular` mode.

**Test environment.** As on Windows, use a dedicated machine with snapshots. Linux: a VM (KVM, VirtualBox...) ⚠️.
macOS: a VM is only possible within Apple's licence terms (normally on Apple hardware, for example with UTM or Tart) ⚠️;
alternatively, a **dedicated user** for testing only, without your data. In any case: dummy accounts and no real data.

## 3. Capture modes

The template created by `claimcheck new` has `capture.mode: local`. **On Linux and macOS start with `regular`**:

```yaml
capture:
  mode: regular
  listen_port: 8080
```

### 3.1 How `regular` works
ClaimCheck starts a proxy on `127.0.0.1:8080`; **the app must use it**. It does not do so by itself: `claimcheck capture` says so at start-up
(the line "regular proxy mode: point the app to ..."). It has to be set for each app, and not all apps honour it.

Open **two terminals**. In the first one start the capture; in the second one start the app with the proxy:

```bash
# terminal 2: only for the app under test (NOT in the capture terminal)
export HTTPS_PROXY=http://127.0.0.1:8080 HTTP_PROXY=http://127.0.0.1:8080
/path/to/the/app
```
Notes on the proxy, ⚠️ standard practice not tested with real apps:
* **Chromium/Electron apps** (VS Code, Jan, Obsidian...): they often ignore environment variables. Try the flag
  `--proxy-server=http://127.0.0.1:8080`.
* **Do not set** the proxy variables in the terminal where `claimcheck capture` runs: the capture itself might use the proxy as its upstream.
* **Flatpak**: the app is sandboxed; the variables must be passed to the sandbox (`flatpak run --env=HTTPS_PROXY=... <app-id>`) ⚠️.
* Apps that ignore every proxy setting: in `regular` mode they **will not be seen** (0 records: the report flags it as
  "capture recorded 0 records", not as a silent app). You need `local` mode or another tool.

If `capture.launch_app: true`, ClaimCheck starts `app.exe_path` inheriting **the environment variables of its own terminal**.
On macOS `exe_path` must be the executable inside the bundle (`/Applications/App.app/Contents/MacOS/<executable>`), not the
`.app` folder (a directory cannot be executed) ⚠️.

### 3.2 Preliminary proxy check ✅ (Linux)
Before a real app, check that the proxy + certificate chain works with the canary (section 6): if the benchmark passes, the proxy and
the addon work.

### 3.3 `local` on Linux ⚠️
* mitmproxy starts a helper program through **`sudo`** ✅ (without `sudo` installed: "Failed to run sudo").
* ClaimCheck starts mitmdump **without a terminal** and with its input closed: a `sudo` asking for a password cannot get an answer.
  The two practical options, both to be tested: run ClaimCheck as root already, or have password-less `sudo` for the duration of the test.
* **Likely trap with root**: mitmproxy uses `~/.mitmproxy` as its certificate folder. If you run as root, `~` may be
  `/root`, and the certificate you installed (your user's) **does not match** the one used by the proxy: all
  HTTPS connections fail (`tls_failed`). Remedy to try: in the manifest `capture.extra_args: ["--set", "confdir=/home/YOUR_USER/.mitmproxy"]`.
* Files in `runs/` created by root belong to root: change the owner (`sudo chown -R $USER runs`) before continuing as a normal user.
* The process name (`app.exe_name`): the kernel truncates the name to **15 characters** in `ps -eo comm`. Check with `pgrep -a <name>`.
* On the test machine `local` mode could not start (microVM): we do not know how it behaves on a real desktop.

### 3.4 `local` on macOS ⚠️
mitmproxy has a macOS-specific component (the Linux venv contains `mitmproxy_linux`, not `mitmproxy_macos`).
Whether and how your version supports per-process capture (and any approvals in System Settings) must be checked
in the mitmproxy documentation for the installed version (`pip list | grep -i mitmproxy`). Until then use `regular`.

## 4. mitmproxy certificate

Without the certificate, HTTPS connections fail and the traffic shows up as **opaque** (docs 02 §4.2). The certificate is generated the first time
mitmdump starts (for example with `claimcheck capture`) in `~/.mitmproxy/mitmproxy-ca-cert.pem`.

### 4.1 Linux, system trust store (Debian/Ubuntu) ✅
```bash
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy-test.crt   # the .crt extension is required
sudo update-ca-certificates
```
Removal:
```bash
sudo rm /usr/local/share/ca-certificates/mitmproxy-test.crt
sudo update-ca-certificates --fresh
```
✅ Tested with `update-ca-certificates` **without** `--fresh`: after removal the same request fails with "SSL certificate problem", so trust
is revoked; but two **orphaned symbolic links** remain in `/etc/ssl/certs` (harmless, untidy). With `--fresh` (which removes them) I did not test it: on the
test machine it would also have regenerated other services' certificates. On your computer it is the recommended form.
Other distributions (Fedora/RHEL: `/etc/pki/ca-trust/source/anchors/` + `update-ca-trust`) ⚠️.

### 4.2 Linux, NSS database (Chromium, Electron) ✅
Many Chromium/Electron apps read the user's NSS database, not the system trust store (package `libnss3-tools`):
```bash
mkdir -p ~/.pki/nssdb && certutil -d sql:$HOME/.pki/nssdb -N --empty-password      # only if it does not exist yet
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n mitmproxy-test -i ~/.mitmproxy/mitmproxy-ca-cert.pem
certutil -d sql:$HOME/.pki/nssdb -L                                                 # check
certutil -d sql:$HOME/.pki/nssdb -D -n mitmproxy-test                               # REMOVAL
```
If `~/.pki/nssdb` already exists with your certificates, do **not** run `-N`: recreating it would delete them.

### 4.3 Other certificate stores ⚠️
Not all apps use the system trust store: Firefox (its own store), Java (`cacerts`), Python with `certifi`, Node
(`NODE_EXTRA_CA_CERTS=~/.mitmproxy/mitmproxy-ca-cert.pem`). Apps with *certificate pinning* will remain opaque: it is a known limit
(docs 02, 09) and the report declares it `INCONCLUSIVE`, not "clean".

### 4.4 macOS ⚠️
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.mitmproxy/mitmproxy-ca-cert.pem
```
Removal: Keychain Access → System → search for "mitmproxy" → delete; or from the command line
`sudo security delete-certificate -c mitmproxy /Library/Keychains/System.keychain`. **After removal, check** in the Keychain Access app
that it is gone: I could not test this.

## 5. Collecting the app's data (complements docs 03)

* Hash: `sha256sum installer` (Linux) / `shasum -a 256 installer` (macOS).
* **`app.install_dir` folder**: it must contain the **installed and unpacked** files. ClaimCheck does not look inside
  compressed containers: `.deb`, `.rpm`, `.AppImage`, `.snap`, `.dmg`, `.pkg`, `.7z`, `.tar.gz` are listed as **not inspectable** and make
  the static scan "incomplete" (verdicts become `INCONCLUSIVE`, not "clean"). Extract or install first:

| Format | How to get the files to scan |
|--------|------------------------------|
| `.deb` | install it, or `dpkg-deb -x package.deb folder/` ✅ (tested: extracts the files; a `.deb` used as `install_dir` is flagged "not inspectable") |
| AppImage | `./App.AppImage --appimage-extract` creates `squashfs-root/` ⚠️ |
| Flatpak | the files are under `/var/lib/flatpak/app/<id>/` or `~/.local/share/flatpak/app/<id>/` ⚠️ |
| Snap | `/snap/<name>/current` ⚠️ |
| macOS `.app` | `/Applications/App.app` (it is already a folder) ⚠️ |
| macOS `.dmg` / `.pkg` | `hdiutil attach` and copy the app / `pkgutil --expand-full` ⚠️ |

* Source repo at the **same version**: `git checkout <tag>` as on Windows. Since 0.2.0 the report warns if the tag does not
  seem to match `app.version`.
* The process name for `local`: see 3.3. Not needed for `regular`, but still useful in `notes.md`.
* Typical user-data paths (useful to find out whether the app writes identifiers): Linux `~/.config/<app>`, `~/.local/share/<app>`;
  macOS `~/Library/Application Support/<app>` ⚠️.

## 6. Running: the canary in bash ✅ (Linux)

Run from the project folder (it must contain `benchmark/`, which is in the source zip but **not** in the wheel):

```bash
claimcheck candidates --make canary          # writes apps/canary.yaml (mode: regular)
claimcheck init apps/canary.yaml --label "canary telemetry"
claimcheck claims
# terminal 1:
claimcheck capture --phase idle --minutes 1
# terminal 2, after ~8 seconds (the proxy must already be running), same port 8080:
python -m claimcheck.canary --behaviour telemetry --proxy http://127.0.0.1:8080 --minutes 0.7 --interval 2
# then, when the capture has finished:
claimcheck classify ; claimcheck score
claimcheck benchmark benchmark/truth/canary-telemetry.yaml
```
Expected outcome ✅: "all expectations met", 4 verdicts and 3 hosts matching the truth (`no_telemetry`, `no_third_party_sharing`,
`privacy_friendly`, `policy_disclosure` = `CONTRADICTED`; `local_first` = `WARNING`). If it does not match, **do not use the tool on real apps**.
Repeat with `--behaviour clean`, `optout-respected`, `optout-ignored` as in docs 10.

With real apps, once the capture has started: launch the app (terminal 2, section 3.1), perform **the fixed usage scenario** (docs 03 §E),
then Ctrl+C in terminal 1 (the capture closes in an orderly way: a second Ctrl+C during saving is ignored).

**Prevent sleep** during capture (an "idle" window during which the computer sleeps is not valid; since 0.2.0 the
system detects it and marks the capture `partial`):
* Linux ✅ (the command exists): `systemd-inhibit --what=idle:sleep claimcheck capture --phase idle --minutes 5`
* macOS ⚠️: `caffeinate -dimsu claimcheck capture --phase idle --minutes 5`

## 7. Testing the software on Linux/macOS

```bash
pip install -e ".[capture,dev]"
pytest                                                  # ✅ Linux: 403 tests
CLAIMCHECK_INTEGRATION=1 pytest tests/test_integration_mitmproxy.py    # ✅ Linux: 4 tests with a real mitmproxy
```
The integration tests use the canary in `regular` mode: they **do not cover** `local` mode.

## 8. Cleanup

Linux ✅: remove the certificate (4.1 and 4.2 with `--fresh` and `certutil -D`), delete the venv, and decide what to do with `runs/`
(it contains raw captures and payload samples: keep them private or delete them). If you downloaded the blocklists: `~/.claimcheck/lists`.
Restore the VM snapshot if you used one.

macOS ⚠️: remove the certificate from the Keychain (4.4) and **check**; if you set a system proxy, disable it
(System Settings → Network → Proxies, or `networksetup -listallnetworkservices` for the list and `networksetup -setsecurewebproxystate "<service>" off`).

## 9. Typical problems

| Symptom | Likely cause | What to do |
|---------|--------------|------------|
| "Failed to run sudo" in the mitmdump log ✅ | `local` mode on Linux without `sudo` | install `sudo`, or use `regular` |
| `capture recorded 0 records` in the report | the app does not use the proxy, or the certificate is not trusted | sections 3.1 and 4; try the canary first |
| `tls_failed` / opaque traffic | certificate not trusted in that specific store, or pinning | 4.2 / 4.3; if it is pinning: a limit of the tool |
| Error "... addon did not start within 25 s" | mitmdump starts but the addon does not (incompatible version, folder not writable) | `claimcheck doctor`, check the log in `logs/mitmdump_*.log` |
| When capturing as root, HTTPS fails | different certificate (`/root/.mitmproxy`) | 3.3, `confdir` option |
| `Permission denied` on `runs/` after a capture as root | files created by root | `sudo chown -R $USER runs` |
| `python3 --version` < 3.11 (macOS) ⚠️ | old system Python | 2, Homebrew |
| Static scan `INCONCLUSIVE` with "compressed containers" | `install_dir` points to a `.deb`/AppImage/`.dmg` | section 5: extract first |

## 10. Checklist to declare a new system "validated"

On a new system (for example your Mac) the tool is "validated" only if **all** these points pass:
1. `pytest` and the 4 integration tests (7) without failures;
2. the 4 canaries (`telemetry`, `clean`, `optout-respected`, `optout-ignored`) with `benchmark` = "all expectations met";
3. certificate installation **and removal** verified (after removal, an HTTPS request through the proxy must fail);
4. for `local` mode (if you will use it): a canary or a known app captured per process, with at least one flow recorded;
5. a capture interrupted with Ctrl+C: status `partial`/`interrupted` and no `mitmdump` process left (`pgrep -a mitmdump`).

If something does not add up, fix this file: the ⚠️ markers exist to be replaced with ✅ **only after** a real test.
