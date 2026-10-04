from __future__ import annotations

from pathlib import Path

import pytest

from claimcheck.context import open_context
from claimcheck.runs import create_run
from helpers import write_manifest


@pytest.fixture()
def runs_root(tmp_path: Path) -> Path:
    return tmp_path / "runs"


@pytest.fixture()
def manifest_file(tmp_path: Path) -> Path:
    return write_manifest(tmp_path / "app.yaml")


@pytest.fixture()
def run_dir(runs_root, manifest_file):
    return create_run(runs_root, manifest_file)


@pytest.fixture()
def ctx(runs_root, run_dir):
    with open_context(runs_root, run_dir.app_slug, run_dir.run_id, write=True) as c:
        yield c


@pytest.fixture(autouse=True)
def _wide_terminal(monkeypatch):
    """Rich wraps tables to the terminal width; a wide fake terminal keeps assertions on output stable."""
    monkeypatch.setenv("COLUMNS", "220")
