# 06 · Managing hardware resources

## Recommended VM requirements

| Resource | Minimum (`doctor`) | Recommended |
|----------|--------------------|-------------|
| CPU | 2 logical cores (warning below) | 4 vCPU |
| Available RAM | 2 GB (warning below) | 8 GB total for the VM |
| Free disk | below 2 GB = FAIL; 10 GB = OK | 60 GB for the VM |

## Where the consumption goes

| Activity | Resource | Order of magnitude |
|----------|----------|--------------------|
| `capture` | disk | ~0.5–1.5 KB per record in the JSONL (with a 512 B payload sample) + a database of similar size. 200,000 records ≈ a few hundred MB |
| `capture` | RAM | mitmdump: tens/hundreds of MB, grows with connections and large bodies |
| `static` | CPU/time | sequential chunked reads; in the test container (1 CPU) ~30 MB/s → 4 GB in about 2–3 minutes |
| `static` | RAM | about 3× `chunk_mb` (8 MB) per worker ≈ 25 MB, independent of file size |
| `classify` | RAM | proportional to the records (lightweight query without payloads); 200,000 records: a few hundred MB at most |
| cloned repo | disk | `--depth 1`, usually < 1 GB |

## Automatic guards during capture

Every `heartbeat_seconds` (5) it checks:
* free disk < `min_free_disk_mb` (2048) → **stops** the capture cleanly (data saved, phase `partial`);
* available RAM < `min_free_ram_mb` (512) → warning (once);
* records > `max_flows` (200000) → **stops** (`partial`).
Before starting, if the disk is already below the threshold, the capture **does not start** and creates no half-written files.

## Tuning (in the run's manifest)

```yaml
capture:
  min_free_disk_mb: 4096
  max_flows: 100000
  store_payload_sample: false   # does not store payload samples: less disk and less sensitive data
  payload_sample_bytes: 256
static:
  workers: 2                    # use what `claimcheck doctor` suggests
  max_file_mb: 200              # larger files are skipped (recorded in the coverage)
  max_total_mb: 2048            # total budget of bytes read (also protects against zip bombs)
  chunk_mb: 4
classify:
  max_dns_lookups: 100          # cap on CNAME resolutions
```
Whatever is skipped because of limits is **written into the coverage** (report and `static` output): a "not found" result
must be read together with what was not scanned.

## Good practice

1. One capture at a time; close browsers and unnecessary apps.
2. Disable sleep/hibernation during capture. If the PC sleeps, the capture skips and the phase turns out short.
3. Keep `runs\` on a **local**, non-synced disk (not OneDrive/Dropbox).
4. Increase `static.workers` only if `doctor` reports free CPU and RAM; with a single CPU leave it at 1.
5. Heavy apps (Electron with many MB): try `static --side repo` first, then `binary`.

## Freeing space without losing data

Safe to delete: `artifacts\repo\` (it is re-cloned), `logs\mitmdump-*.log` after checking the capture.
**Do not delete** `raw\` (source of truth: the database can be rebuilt from it) or `store.sqlite`.
To archive: `claimcheck export`, check the zip, then move the run off the working disk.

## Quick diagnosis

`claimcheck doctor` (machine state), `claimcheck status` (rows stored), the status line during capture
(`disk_free`, `ram_avail`), and `Get-Process mitmdump | Select WS` for the proxy's memory.
