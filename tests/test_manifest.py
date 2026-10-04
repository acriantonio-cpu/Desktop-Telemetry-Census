from __future__ import annotations

import pytest
import yaml

from claimcheck.errors import ManifestError
from claimcheck.manifest import load_manifest, parse_manifest, render_template


def test_minimal_manifest_gets_defaults():
    m = parse_manifest({"app": {"name": "My App", "exe_name": "a.exe"}})
    assert m.app.slug == "my-app"
    assert m.capture.mode == "local" and m.capture.idle_minutes == 5
    assert m.static.workers == 1 and m.classify.telemetry_threshold == 0.7


def test_template_roundtrip_is_valid():
    m = parse_manifest(yaml.safe_load(render_template("Some Tool", exe_name="t.exe", first_party=["t.io"])))
    assert m.app.name == "Some Tool" and m.first_party_domains == ["t.io"]


def test_all_problems_are_reported_together():
    with pytest.raises(ManifestError) as e:
        parse_manifest({"app": {}, "capture": {"mode": "weird", "listen_port": 70000, "idle_minutes": "x"},
                        "static": {"workers": 0}, "classify": {"suspect_threshold": 0.9, "telemetry_threshold": 0.5}})
    msg = str(e.value)
    for needle in ("app.name", "capture.mode", "listen_port", "idle_minutes", "static.workers", "suspect_threshold"):
        assert needle in msg


def test_unknown_keys_warn_but_do_not_fail():
    m = parse_manifest({"app": {"name": "A", "exe_name": "a.exe", "colour": "x"}, "extra": 1})
    assert any("colour" in w for w in m.warnings) and any("extra" in w for w in m.warnings)


def test_documents_validated():
    with pytest.raises(ManifestError) as e:
        parse_manifest({"app": {"name": "A"}, "sources": {"documents": [{"type": "ftp", "location": "", "role": "x"}]}})
    assert "documents[0].type" in str(e.value) and "role" in str(e.value) and "location" in str(e.value)


def test_relative_paths_resolve_against_manifest_dir(tmp_path):
    f = tmp_path / "m.yaml"
    f.write_text(yaml.safe_dump({"app": {"name": "A", "exe_name": "a.exe", "install_dir": "inst"},
                                 "sources": {"repo_path": "repo"}}), encoding="utf-8")
    m = load_manifest(f)
    assert m.app.install_dir == str(tmp_path / "inst") and m.sources.repo_path == str(tmp_path / "repo")


def test_bad_yaml_and_missing_file(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("a: [unclosed", encoding="utf-8")
    with pytest.raises(ManifestError):
        load_manifest(bad)
    with pytest.raises(ManifestError):
        load_manifest(tmp_path / "nope.yaml")


def test_type_confusion_is_rejected():
    with pytest.raises(ManifestError):
        parse_manifest({"app": {"name": "A"}, "capture": {"launch_app": "yes"}})
    with pytest.raises(ManifestError):
        parse_manifest(["not", "a", "mapping"])
