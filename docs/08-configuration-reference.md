# 08 · Reference: manifest, commands, data model

## Manifest (YAML) — all keys

Unknown keys produce a **warning** (not an error). All validation errors are listed together.

| Section.key | Default | Notes |
|-------------|---------|-------|
| `schema_version` | 1 | |
| `app.name` | — (required) | |
| `app.slug` | from `name` | folder name `runs/<slug>/` |
| `app.version`, `homepage`, `stack` | empty | documentation/reproducibility |
| `app.exe_name` | empty | required with `capture.mode: local` |
| `app.exe_path` | empty | required with `--launch` |
| `app.install_dir` | empty | file/folder scanned by `static` (binary side) |
| `app.installer_sha256` | empty | reproducibility |
| `first_party_domains` | [] | vendor domains |
| `allowed_domains` | [] | expected/benign domains: they switch off the heuristics, **not** the match with a known vendor |
| `sources.repo_path` / `repo_url` / `repo_ref` | empty | local repo, or URL (`https://`, `http://`, `ssh://`, `git@`) + tag/branch |
| `sources.documents[]` | [] | `{type: url\|file, location, role: readme\|homepage\|privacy_policy\|other}` |
| `capture.mode` | `local` | `local` \| `regular` |
| `capture.listen_port` | 8080 | `regular` only |
| `capture.idle_minutes` / `use_minutes` / `optout_minutes` | 5 / 0 / 5 | 0 = until Ctrl+C |
| `capture.launch_app` / `kill_app_at_end` | false / true | |
| `capture.mitmdump` | `mitmdump` | command (a full path also works, quotes are fine) |
| `capture.min_free_disk_mb` / `min_free_ram_mb` | 2048 / 512 | |
| `capture.max_flows` | 200000 | |
| `capture.store_payload_sample` / `payload_sample_bytes` | true / 512 | redacted sample of the body |
| `capture.heartbeat_seconds` | 5 | frequency of checks and of the status line |
| `capture.canary_suffix` | empty | hosts answered locally (canary only) |
| `capture.extra_args` | [] | extra arguments for mitmdump |
| `static.max_file_mb` / `max_total_mb` / `workers` / `chunk_mb` | 300 / 4096 / 1 / 8 | |
| `static.skip_runtime_files` | true | skips known runtimes (electron.exe, chrome.dll, …) |
| `static.skip_globs`, `runtime_files` | built-in lists | skipped extensions/names |
| `static.extra_signatures` | [] | YAML files with additional signatures |
| `classify.blocklists` | [] | hosts/AdGuard/Disconnect lists; those in `~/.claimcheck/lists` are included |
| `classify.resolve_cname` | true | detects CNAME cloaking |
| `classify.telemetry_threshold` / `suspect_threshold` | 0.7 / 0.4 | score thresholds |
| `classify.max_dns_lookups` / `dns_timeout` | 200 / 3.0 | |

Relative paths are resolved against the folder of the **original** manifest.
**The manifest is trusted configuration:** it can specify commands to run (`capture.mitmdump`, `extra_args`, `exe_path`).
Do not use manifests of unknown origin without reading them.

## Commands

| Command | Purpose |
|---------|---------|
| `version`, `doctor [--online]` | version; environment check |
| `new NAME`, `candidates [--tier --role --show --make]` | empty manifest / app catalogue |
| `fetch-lists`, `addon-path` | downloads the Disconnect list; path of the mitmproxy addon |
| `init MANIFEST [--label]`, `runs`, `status` | create a run; list; status |
| `claims`, `static [--side]`, `capture --phase`, `import-flows`, `ingest` | data acquisition |
| `classify`, `score`, `report [--open]` | analysis and report |
| `resume [--with-capture]`, `run MANIFEST` | automation |
| `show TABLE`, `sql "SELECT…"`, `events` | read-only inspection |
| `exclude ID`, `include ID` | exclude/readmit an attempt from the analysis |
| `export [--out]`, `benchmark TRUTH…` | zip of the run; comparison with ground truth |
| `verify` | SHA-256 integrity check of the raw files |

## Data model (SQLite, `store.sqlite`)

| Table | Content | Append-only |
|-------|---------|-------------|
| `attempts` | one record per phase execution (status, parameters, summary, notes, `excluded`) | not deletable |
| `raw_files` | registered JSONL files, lines imported, sha256, `complete` | not deletable |
| `flows` | traffic records (host, method, path, payload keys, id hashes, …) | yes |
| `claims`, `disclosed` | promises; providers mentioned in the policy | yes |
| `static_evidence` | SDKs found (side, kind, location) | yes |
| `labels`, `dns_records` | labels per host/phase; CNAME chains | yes |
| `verdicts` | verdicts with evidence | yes |
| `events`, `meta` | journal; tool version | `events` yes |

Attempt rule: captures add up all `done`/`partial` attempts that are not excluded; analyses
(`claims`, `static`, `classify`, `score`) use the latest `done` one. An analysis is **stale** if one of its inputs is newer
(transitively: new data → classify → score → report).

## Attempt states
`running` → `done` | `partial` | `failed` | `interrupted` (orphaned `running` attempts become `interrupted` when the run is reopened).

## Raw traffic format (`raw/*.jsonl`)
One JSON object per line: `meta`, `flow` (http), `sni`, `tls_failed`, `error`, `addon_error`. E-mails, UUIDs, tokens and long numbers
are redacted in the samples; identifiers are stored only as SHA-256 hashes (12 characters). Caution: the hash of a *low-entropy* value
(e.g. a plain-text e-mail address) can be guessed with a dictionary: use dummy accounts and do not publish the raw data.
