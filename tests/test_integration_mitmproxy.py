"""Real end-to-end validation: mitmproxy + our addon + the canary app + the full pipeline vs ground truth.

Run with:  CLAIMCHECK_INTEGRATION=1 pytest tests/test_integration_mitmproxy.py -s
Needs mitmproxy (pip install ".[capture]"). Uses only loopback + the canary responder: no real vendor is contacted.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from claimcheck.benchmark import evaluate, load_truth, observed_from_store
from claimcheck.context import open_context
from claimcheck.dynamic.capture import run_capture
from claimcheck.pipeline import phase_claims, phase_classify, phase_score, run_phase
from claimcheck.runs import create_run
from helpers import write_manifest

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmark"
TRUTH = ROOT / "benchmark/truth"


def _mitmdump() -> str | None:
    return shutil.which("mitmdump") or (str(Path(sys.executable).parent / "mitmdump") if (Path(sys.executable).parent / "mitmdump").exists() else None)


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.environ.get("CLAIMCHECK_INTEGRATION") != "1", reason="set CLAIMCHECK_INTEGRATION=1 to run"),
    pytest.mark.skipif(_mitmdump() is None, reason="mitmdump not installed"),
]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_port(port: int, timeout: float = 40.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        with socket.socket() as s:
            s.settimeout(0.5)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.3)
    return False


def _capture_with_canary(ctx, phase: str, port: int, canary_args: list[str], minutes: float = 0.4) -> None:
    result = {}

    def cap():
        result["r"] = run_phase(ctx, phase, lambda a: run_capture(ctx, a, phase, minutes=minutes))

    t = threading.Thread(target=cap)
    t.start()
    assert _wait_port(port), "mitmdump never started listening"
    out = subprocess.run([sys.executable, "-m", "claimcheck.canary", "--proxy", f"http://127.0.0.1:{port}", "--minutes", str(minutes - 0.15), "--interval", "2", *canary_args],  # noqa: S603
                         capture_output=True, text=True, timeout=120)
    print(out.stdout[-600:])
    t.join(timeout=120)
    assert result["r"].status == "done", result["r"]


def _setup(tmp_path, runs_root, port):
    mf = write_manifest(
        tmp_path / "canary.yaml", app={"name": "canary", "exe_name": "python"}, first_party_domains=["canary-app.example"],
        sources={"documents": [{"type": "file", "location": str(BENCH / "canary_claims.md"), "role": "readme"},
                               {"type": "file", "location": str(BENCH / "canary_policy.md"), "role": "privacy_policy"}]},
        capture={"mode": "regular", "listen_port": port, "mitmdump": _mitmdump(), "heartbeat_seconds": 2,
                 "canary_suffix": "eu.i.posthog.com,o0.ingest.sentry.io,canary-app.example"},
    )
    rd = create_run(runs_root, mf)
    return open_context(runs_root, rd.app_slug, rd.run_id)


def _analyse(ctx, truth_file):
    run_phase(ctx, "claims", lambda a: phase_claims(ctx, a))
    run_phase(ctx, "classify", lambda a: phase_classify(ctx, a))
    run_phase(ctx, "score", lambda a: phase_score(ctx, a))
    verdicts, labels = observed_from_store(ctx.store)
    res = evaluate(load_truth(TRUTH / truth_file), verdicts, labels)
    for r in res["rows"]:
        print(r)
    return res


def test_canary_telemetry_is_detected(tmp_path, runs_root):
    port = _free_port()
    with _setup(tmp_path, runs_root, port) as ctx:
        _capture_with_canary(ctx, "capture_idle", port, ["--behaviour", "telemetry"])
        flows = ctx.store.select("flows")
        hosts = {f["host"] for f in flows}
        assert {"eu.i.posthog.com", "o0.ingest.sentry.io", "api.canary-app.example"} <= hosts, hosts
        assert any(f["id_hashes"] for f in flows)  # persistent identifier hashed by the real addon
        assert not any("123e4567" in (f["sample"] or "") for f in flows)
        res = _analyse(ctx, "canary-telemetry.yaml")
        assert res["all_match"], res["rows"]


def test_canary_clean_app_raises_no_false_positive(tmp_path, runs_root):
    port = _free_port()
    with _setup(tmp_path, runs_root, port) as ctx:
        _capture_with_canary(ctx, "capture_idle", port, ["--behaviour", "clean"])
        res = _analyse(ctx, "canary-clean.yaml")
        assert res["all_match"], res["rows"]


def _optout_scenario(tmp_path, runs_root, behaviour: str, truth: str):
    port = _free_port()
    flag = tmp_path / "optout.flag"
    with _setup(tmp_path, runs_root, port) as ctx:
        _capture_with_canary(ctx, "capture_idle", port, ["--behaviour", behaviour, "--flag-file", str(flag)])
        flag.write_text("user disabled telemetry", encoding="utf-8")  # simulated opt-out
        _capture_with_canary(ctx, "capture_optout", port, ["--behaviour", behaviour, "--flag-file", str(flag)])
        return _analyse(ctx, truth)


def test_canary_ignoring_optout_is_caught(tmp_path, runs_root):
    res = _optout_scenario(tmp_path, runs_root, "optout-ignored", "canary-optout-ignored.yaml")
    assert res["all_match"], res["rows"]


def test_canary_respecting_optout_is_not_accused(tmp_path, runs_root):
    res = _optout_scenario(tmp_path, runs_root, "optout-respected", "canary-optout-respected.yaml")
    assert res["all_match"], res["rows"]
