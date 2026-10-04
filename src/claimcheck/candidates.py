"""Catalogue of candidate apps (data/candidates.yaml) + manifest generation."""

from __future__ import annotations

import json
from importlib import resources

import yaml

from claimcheck.errors import ClaimCheckError
from claimcheck.manifest import render_template


def load_catalogue() -> dict:
    text = resources.files("claimcheck").joinpath("data/candidates.yaml").read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    if not isinstance(data, dict) or not isinstance(data.get("apps"), list):
        raise ClaimCheckError("candidates.yaml is malformed")
    return data


def list_candidates(tier: str | None = None, role: str | None = None) -> list[dict]:
    apps = load_catalogue()["apps"]
    return [a for a in apps if (not tier or a.get("tier") == tier.upper()) and (not role or a.get("role") == role)]


def get_candidate(slug: str) -> dict:
    for a in load_catalogue()["apps"]:
        if a["slug"] == slug:
            return a
    known = ", ".join(a["slug"] for a in load_catalogue()["apps"])
    raise ClaimCheckError(f"Unknown candidate '{slug}'. Known: {known}")


def manifest_text_for(slug: str) -> str:
    a = get_candidate(slug)
    text = render_template(
        name=a["name"], slug=a["slug"], homepage=a.get("homepage", ""), stack=a.get("stack", ""),
        exe_name=a.get("exe_name", ""), first_party=a.get("first_party_domains", []), repo_url=a.get("repo_url", ""),
        documents=a.get("documents") or None,
    )
    def _replace(src: str, old: str, new: str) -> str:
        if old not in src:  # the template changed under us: never silently emit a manifest without the tweak
            raise ClaimCheckError(f"internal error: manifest template no longer contains {old!r}")
        return src.replace(old, new)

    if a.get("allowed_domains"):
        text = _replace(text, "allowed_domains: []", "allowed_domains: [" + ", ".join(json.dumps(d) for d in a["allowed_domains"]) + "]")
    if slug == "canary":
        text = _replace(text, "mode: local                   # local", "mode: regular                 # regular = HTTP proxy (the canary uses --proxy)")
        text = _replace(text, "  launch_app: false", '  launch_app: false\n  canary_suffix: "eu.i.posthog.com,o0.ingest.sentry.io,canary-app.example"')
    header = (
        f"# Generated from the built-in catalogue (tier {a.get('tier')}, role {a.get('role')}, status {a.get('status')}).\n"
        f"# Why this app: {a.get('why', '')}\n"
        f"# Verify the public claims yourself at: {a.get('verify_at', '')}\n"
        "# TODO before running: set app.version, app.install_dir, sources.repo_path (same tag as the release) and confirm app.exe_name.\n"
    )
    return header + text
