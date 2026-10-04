"""Synthetic 'app' with KNOWN behaviour, used to validate ClaimCheck itself (ground truth).

It only sends requests through the capture proxy; with the manifest's `capture.canary_suffix` the addon
answers them locally, so no data ever reaches PostHog/Sentry. Behaviours:
  clean              only first-party benign requests
  telemetry          + PostHog-like events and Sentry-like envelopes every interval
  optout-respected   like telemetry, but stops telemetry once --flag-file exists (simulated opt-out)
  optout-ignored     like telemetry, and KEEPS sending after the flag file exists (privacy-washing case)
"""

from __future__ import annotations

import argparse
import json
import os
import time
import uuid
from pathlib import Path

BEHAVIOURS = ("clean", "telemetry", "optout-respected", "optout-ignored")
INSTALL_ID = str(uuid.uuid4())  # stable for the whole process: a persistent identifier


def _post(session, url: str, body: bytes, ctype: str) -> str:
    try:
        r = session.post(url, data=body, headers={"Content-Type": ctype, "X-Claimcheck-Canary": "1"}, timeout=10, verify=False)  # noqa: S501
        return f"{r.status_code}"
    except Exception as e:  # noqa: BLE001
        return f"error:{type(e).__name__}"


def run(proxy: str, minutes: float, interval: float, behaviour: str, flag_file: str, log=print) -> int:
    import requests
    import urllib3

    urllib3.disable_warnings()
    s = requests.Session()
    s.verify = False  # noqa: S501 - the canary talks only to the local capture proxy
    s.trust_env = False  # env CA bundles would silently override verify=False (requests quirk)
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    end = time.time() + minutes * 60 if minutes > 0 else float("inf")
    n = 0
    log(f"canary start: behaviour={behaviour} proxy={proxy or '(none)'} interval={interval}s minutes={minutes}")
    while time.time() < end:
        n += 1
        opted_out = bool(flag_file) and Path(flag_file).exists()
        try:
            r = s.get("https://api.canary-app.example/v1/config", headers={"X-Claimcheck-Canary": "1"}, timeout=10, verify=False)  # noqa: S501
            status = str(r.status_code)
        except Exception as e:  # noqa: BLE001
            status = f"error:{type(e).__name__}"
        log(f"[{n}] first-party GET -> {status}")
        send_tele = behaviour in ("telemetry", "optout-ignored") or (behaviour == "optout-respected" and not opted_out)
        if send_tele:
            ev = {"api_key": "phc_canary", "event": "app_opened", "distinct_id": INSTALL_ID,
                  "properties": {"$os": "windows", "app_version": "1.0.0", "session_id": str(uuid.uuid4()), "seq": n},
                  "timestamp": time.time()}
            log(f"[{n}] posthog-like POST -> {_post(s, 'https://eu.i.posthog.com/capture/', json.dumps(ev).encode(), 'application/json')}")
            env = json.dumps({"event_id": uuid.uuid4().hex, "sdk": {"name": "canary"}}) + "\n" + json.dumps({"type": "event"}) + "\n" + json.dumps({"level": "info", "message": "heartbeat", "install": INSTALL_ID})
            log(f"[{n}] sentry-like POST  -> {_post(s, 'https://o0.ingest.sentry.io/api/0/envelope/', env.encode(), 'application/x-sentry-envelope')}")
        elif behaviour == "optout-respected":
            log(f"[{n}] opted out: telemetry suppressed")
        time.sleep(interval)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m claimcheck.canary", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--proxy", default=os.environ.get("HTTPS_PROXY", "http://127.0.0.1:8080"), help="capture proxy URL (mitmproxy regular mode)")
    p.add_argument("--minutes", type=float, default=0, help="0 = run until Ctrl+C")
    p.add_argument("--interval", type=float, default=10.0, help="seconds between rounds")
    p.add_argument("--behaviour", choices=BEHAVIOURS, default="telemetry")
    p.add_argument("--flag-file", default="canary_optout.flag", help="create this file to simulate 'user disabled telemetry'")
    a = p.parse_args(argv)
    try:
        return run(a.proxy, a.minutes, a.interval, a.behaviour, a.flag_file)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
