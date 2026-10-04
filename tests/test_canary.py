from __future__ import annotations

import json
import subprocess
import sys

import pytest

from claimcheck import canary


class FakeSession:
    """Records requests instead of sending them."""

    calls: list[tuple[str, str, bytes | None]] = []

    def __init__(self):
        self.proxies, self.verify, self.trust_env = {}, True, True

    def _resp(self):
        class R:
            status_code = 200

        return R()

    def get(self, url, **kw):
        FakeSession.calls.append(("GET", url, None))
        return self._resp()

    def post(self, url, data=None, **kw):
        FakeSession.calls.append(("POST", url, data))
        return self._resp()


@pytest.fixture()
def fake_requests(monkeypatch):
    import requests

    FakeSession.calls = []
    monkeypatch.setattr(requests, "Session", FakeSession)
    return FakeSession


def _run(behaviour, flag=""):
    logs = []
    canary.run("http://127.0.0.1:1", minutes=0.004, interval=0.05, behaviour=behaviour, flag_file=flag, log=logs.append)
    return {(m, u.split("/")[2]) for m, u, _ in FakeSession.calls}, logs


def test_clean_behaviour_sends_only_first_party(fake_requests):
    hosts, _ = _run("clean")
    assert hosts == {("GET", "api.canary-app.example")}


def test_telemetry_behaviour_sends_posthog_and_sentry_with_persistent_id(fake_requests):
    hosts, _ = _run("telemetry")
    assert {("POST", "eu.i.posthog.com"), ("POST", "o0.ingest.sentry.io")} <= hosts
    ids = {json.loads(d)["distinct_id"] for m, u, d in FakeSession.calls if "posthog" in u}
    assert ids == {canary.INSTALL_ID}  # same identifier in every event, like a real analytics SDK


def test_optout_respected_stops_after_flag_file_exists(fake_requests, tmp_path):
    flag = tmp_path / "flag"
    before, _ = _run("optout-respected", str(flag))
    assert ("POST", "eu.i.posthog.com") in before
    flag.write_text("x")
    FakeSession.calls = []
    after, logs = _run("optout-respected", str(flag))
    assert after == {("GET", "api.canary-app.example")} and any("opted out" in m for m in logs)


def test_optout_ignored_keeps_sending_after_flag_file(fake_requests, tmp_path):
    flag = tmp_path / "flag"
    flag.write_text("x")
    hosts, _ = _run("optout-ignored", str(flag))
    assert ("POST", "eu.i.posthog.com") in hosts  # the privacy-washing case


def test_proxy_is_applied_and_env_ca_bundles_are_ignored(fake_requests, monkeypatch):
    seen = {}
    orig = FakeSession.__init__

    def spy(self):
        orig(self)
        seen["s"] = self

    monkeypatch.setattr(FakeSession, "__init__", spy)
    _run("clean")
    assert seen["s"].proxies == {"http": "http://127.0.0.1:1", "https": "http://127.0.0.1:1"} and seen["s"].trust_env is False


def test_cli_parses_and_module_entrypoint_works():
    out = subprocess.run([sys.executable, "-m", "claimcheck.canary", "--help"], capture_output=True, text=True, timeout=30)  # noqa: S603
    assert out.returncode == 0 and "--behaviour" in out.stdout and "optout-ignored" in out.stdout


def test_python_dash_m_claimcheck_runs():
    out = subprocess.run([sys.executable, "-m", "claimcheck", "version"], capture_output=True, text=True, timeout=30)  # noqa: S603
    assert out.returncode == 0 and out.stdout.startswith("claimcheck")
