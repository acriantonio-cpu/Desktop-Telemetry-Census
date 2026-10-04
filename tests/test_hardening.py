"""Regression tests for problems found during the security/robustness audit."""

from __future__ import annotations

import json
import zipfile

import pytest

from claimcheck import pipeline
from claimcheck.dynamic.ingest import ingest_all
from claimcheck.errors import ManifestError
from claimcheck.manifest import StaticCfg, parse_manifest
from claimcheck.signatures import load_signatures
from claimcheck.static.scanner import scan_install
from claimcheck.store import Store, StoreError
from helpers import http_record


def _m(**src):
    return {"app": {"name": "A", "exe_name": "a"}, "sources": src}


# ---- git argument injection through a hostile manifest -------------------------------------------
@pytest.mark.parametrize("url", ["--upload-pack=touch /tmp/x", "-oProxyCommand=evil", "file:///etc/passwd", "ext::sh -c id", "https://ok.com/a b"])
def test_hostile_repo_url_is_rejected(url):
    with pytest.raises(ManifestError, match="repo_url"):
        parse_manifest(_m(repo_url=url))


@pytest.mark.parametrize("ref", ["--exec=evil", "-x", "a b", "v1;rm -rf", "$(id)"])
def test_hostile_repo_ref_is_rejected(ref):
    with pytest.raises(ManifestError, match="repo_ref"):
        parse_manifest(_m(repo_url="https://github.com/a/b", repo_ref=ref))


@pytest.mark.parametrize("url,ref", [("https://github.com/a/b.git", "v1.2.3"), ("git@github.com:a/b.git", "release/1.x"), ("ssh://git@host/a/b", "")])
def test_legitimate_repo_settings_are_accepted(url, ref):
    assert parse_manifest(_m(repo_url=url, repo_ref=ref)).sources.repo_url == url


def test_git_clone_command_ends_option_parsing(ctx, monkeypatch):
    seen = {}
    monkeypatch.setattr(pipeline, "resolve_command", lambda c: ["git"])
    monkeypatch.setattr(pipeline.subprocess, "run", lambda cmd, **kw: seen.setdefault("cmd", cmd))
    ctx.manifest.sources.repo_url, ctx.manifest.sources.repo_ref = "https://github.com/a/b", "v1"
    pipeline.ensure_repo(ctx)
    cmd = seen["cmd"]
    assert cmd[cmd.index("--") + 1] == "https://github.com/a/b" and cmd.index("--branch") < cmd.index("--")


# ---- path traversal through a shared/hostile run -------------------------------------------------
def test_ingest_refuses_raw_paths_outside_the_run_folder(ctx, tmp_path):
    secret = tmp_path / "secret.jsonl"
    secret.write_text(json.dumps(http_record(host="outside.example")) + "\n", encoding="utf-8")
    att = ctx.store.begin_attempt("capture_idle")
    ctx.store.register_raw_file(att, "capture_idle", "../../../../" + str(secret).lstrip("/"))
    msgs = []
    stats = ingest_all(ctx.store, ctx.run, True, lambda lvl, m: msgs.append(m))
    assert stats[0]["inserted"] == 0 and ctx.store.counts()["flows"] == 0
    assert any("outside the run folder" in m for m in msgs)


# ---- silent addon failures now leave a trace that ingest surfaces ------------------------------
def test_addon_error_records_are_reported_by_ingest(ctx):
    att = ctx.store.begin_attempt("capture_idle")
    p = ctx.run.raw_dir / "e.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in [{"type": "addon_error", "where": "response", "error": "KeyError: x"}, http_record()]) + "\n", encoding="utf-8")
    ctx.store.register_raw_file(att, "capture_idle", "raw/e.jsonl")
    msgs = []
    stats = ingest_all(ctx.store, ctx.run, True, lambda lvl, m: msgs.append(m))
    assert stats[0]["addon_errors"] == 1 and stats[0]["inserted"] == 1 and any("KeyError" in m for m in msgs)


# ---- ingest memory: streaming, not slurping ----------------------------------------------------
def test_ingest_handles_many_lines_in_batches(ctx):
    att = ctx.store.begin_attempt("capture_idle")
    p = ctx.run.raw_dir / "big.jsonl"
    with open(p, "w", encoding="utf-8") as fh:
        for i in range(5000):
            fh.write(json.dumps(http_record(ts=1000.0 + i)) + "\n")
    ctx.store.register_raw_file(att, "capture_idle", "raw/big.jsonl")
    assert ingest_all(ctx.store, ctx.run, True, lambda *a: None)[0]["inserted"] == 5000
    assert ctx.store.counts()["flows"] == 5000


def test_lean_flow_query_drops_heavy_columns(ctx):
    att = ctx.store.begin_attempt("capture_idle")
    p = ctx.run.raw_dir / "l.jsonl"
    p.write_text(json.dumps(http_record(sample="X" * 500)) + "\n", encoding="utf-8")
    ctx.store.register_raw_file(att, "capture_idle", "raw/l.jsonl")
    ingest_all(ctx.store, ctx.run, True, lambda *a: None)
    lean = ctx.store.flows_for_classification([att])
    assert len(lean) == 1 and "sample" not in lean[0] and "features" not in lean[0]
    assert lean[0]["payload_keys"] == ["event", "distinct_id", "properties"] and lean[0]["id_hashes"] == ["abc123def456"]
    assert ctx.store.flows_for_classification([]) == []


# ---- store: ORDER BY is validated ---------------------------------------------------------------
def test_select_order_is_validated(tmp_path):
    with Store(tmp_path / "s.sqlite") as st:
        assert st.select("claims", order="id DESC") == []
        for bad in ("id; DROP TABLE claims", "id, (SELECT 1)", "1 OR 1=1"):
            with pytest.raises(StoreError, match="ORDER BY"):
                st.select("claims", order=bad)


# ---- static scan: decompressed archive content is budgeted (zip bomb) ---------------------------
def test_zip_bomb_is_stopped_by_the_total_budget(tmp_path):
    root = tmp_path / "app"
    root.mkdir()
    with zipfile.ZipFile(root / "bomb.zip", "w", zipfile.ZIP_DEFLATED) as z:
        for i in range(30):
            z.writestr(f"e{i}.bin", b"\0" * (1024 * 1024))  # 30 MB of zeros compress to ~30 KB
    res = scan_install(root, load_signatures(), StaticCfg(max_total_mb=5, max_file_mb=5))
    assert res.coverage["bytes_scanned"] <= 6 * 1024 * 1024
    assert res.coverage["archive_entries_skipped"] >= 20
