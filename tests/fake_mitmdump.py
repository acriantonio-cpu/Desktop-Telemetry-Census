"""Stand-in for mitmdump used by tests: honours `--set claimcheck_out=PATH`, appends JSONL records, stops on SIGINT/SIGTERM.

Env FAKE_MITM_MODE: 'exit_early' (crash at start) | 'no_addon' (never writes) | default (writes a flow every 0.2 s).
"""
import json
import os
import signal
import sys
import time

out = next((a.split("=", 1)[1] for a in sys.argv if a.startswith("claimcheck_out=")), None)
mode = os.environ.get("FAKE_MITM_MODE", "")
running = True


def stop(*_):
    global running
    running = False


signal.signal(signal.SIGINT, stop)
signal.signal(signal.SIGTERM, stop)
if mode == "exit_early":
    print("fake mitmdump: simulated startup failure", file=sys.stderr)
    sys.exit(3)
if mode == "no_addon":
    while running:
        time.sleep(0.1)
    sys.exit(0)
fh = open(out, "a", encoding="utf-8", newline="\n")
fh.write(json.dumps({"type": "meta", "addon_version": "test"}) + "\n")
fh.flush()
i = 0
while running:
    i += 1
    rec = {"type": "flow", "ts": time.time(), "host": "eu.i.posthog.com", "sni": "eu.i.posthog.com", "port": 443, "scheme": "https",
           "method": "POST", "path": "/capture/", "query_keys": [], "status": 200, "req_bytes": 300, "resp_bytes": 2,
           "req_ct": "application/json", "payload_keys": ["event", "distinct_id", "properties"], "id_hashes": ["abc"], "sample": "", "features": {}}
    fh.write(json.dumps(rec) + "\n")
    fh.flush()
    time.sleep(0.2)
fh.close()
