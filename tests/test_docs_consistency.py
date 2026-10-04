"""Docs must not drift from the CLI: every `claimcheck <command>` mentioned must exist."""

from __future__ import annotations

import re
from pathlib import Path

import typer.main

from claimcheck.cli import app

ROOT = Path(__file__).resolve().parent.parent
COMMANDS = set(typer.main.get_command(app).commands)
PATTERN = re.compile(r"(?<![\w.\-/\\])claimcheck (?:--?[\w-]+(?: (?![a-z-]+ )\S+)? )*([a-z][a-z-]+)")
IGNORE_WORDS = {"contributors", "is", "the", "e", "che"}  # prose in the README/LICENSE / Italian prose


def _files():
    return [*ROOT.glob("docs/*.md"), ROOT / "README.md", ROOT / "tools" / "README.md"]


def test_every_documented_command_exists():
    bad = []
    for f in _files():
        if not f.exists():
            continue
        for line in f.read_text(encoding="utf-8").splitlines():
            for m in PATTERN.finditer(line):
                if m.group(1) not in COMMANDS and m.group(1) not in IGNORE_WORDS:
                    bad.append((f.name, m.group(1), line.strip()[:80]))
    assert not bad, bad


def test_docs_referenced_from_code_exist():
    src = "\n".join(p.read_text(encoding="utf-8") for p in (ROOT / "src").rglob("*.py"))
    for name in set(re.findall(r"docs/(\d\d-[\w-]+\.md)", src)):
        assert (ROOT / "docs" / name).exists(), name


def test_readme_lists_every_doc_file():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for f in (ROOT / "docs").glob("*.md"):
        assert f.name in readme, f.name


def test_documented_manifest_keys_are_valid():
    """Keys listed in docs/08 exist in the manifest dataclasses."""
    import dataclasses

    from claimcheck.manifest import AppInfo, CaptureCfg, ClassifyCfg, Sources, StaticCfg

    valid = {f"{s}.{f.name}" for s, c in [("app", AppInfo), ("sources", Sources), ("capture", CaptureCfg), ("static", StaticCfg), ("classify", ClassifyCfg)] for f in dataclasses.fields(c)}
    text = (ROOT / "docs/08-configuration-reference.md").read_text(encoding="utf-8")
    for key in re.findall(r"`((?:app|sources|capture|static|classify)\.[a-z_]+)`", text):
        assert key in valid, key
