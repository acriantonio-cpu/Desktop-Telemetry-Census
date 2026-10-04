"""Import flows captured elsewhere: claimcheck JSONL or HAR (browser devtools, Fiddler, Charles, mitmproxy)."""

from __future__ import annotations

import base64
import json
import shutil
from datetime import datetime
from pathlib import Path
from urllib.parse import urlencode, urlsplit

from claimcheck.dynamic.addon import build_flow_record
from claimcheck.dynamic.ingest import ingest_all
from claimcheck.errors import ClaimCheckError
from claimcheck.models import CAPTURE_SHORT, DONE
from claimcheck.util import jdump, unique_path


MAX_HAR_BYTES = 300 * 1024 * 1024  # HAR is loaded as ONE JSON document: refuse what would exhaust RAM


def _har_body(post: dict) -> bytes:
    text = post.get("text")
    if text:
        if post.get("encoding") == "base64":  # some exporters base64 the body
            try:
                return base64.b64decode(text, validate=False)
            except (ValueError, TypeError):
                return b""
        return str(text).encode("utf-8", "replace")
    params = post.get("params")
    if isinstance(params, list):  # form posts often come as name/value pairs, without `text`
        pairs = [(str(x.get("name", "")), str(x.get("value", ""))) for x in params if isinstance(x, dict)]
        return urlencode(pairs).encode("utf-8")
    return b""


def har_to_records(har: dict, sample_bytes: int = 512, store_sample: bool = True, stats: dict | None = None) -> list[dict]:
    entries = ((har or {}).get("log") or {}).get("entries") if isinstance(har, dict) and isinstance((har or {}).get("log"), dict) else None
    if not isinstance(entries, list):
        raise ClaimCheckError("Not a HAR file: missing log.entries")
    stats = stats if stats is not None else {}
    stats["skipped"] = 0
    out = []
    for e in entries:
        if not isinstance(e, dict) or not isinstance(e.get("request"), dict):
            stats["skipped"] += 1
            continue
        req, resp = e.get("request") or {}, e.get("response") if isinstance(e.get("response"), dict) else {}
        url = req.get("url", "")
        u = urlsplit(url)
        if not u.hostname:
            continue
        try:
            ts = datetime.fromisoformat(e.get("startedDateTime", "").replace("Z", "+00:00")).timestamp()
        except ValueError:
            ts = 0.0
        post = req.get("postData") if isinstance(req.get("postData"), dict) else {}
        body = _har_body(post)
        headers = {h.get("name", ""): h.get("value", "") for h in (req.get("headers") or []) if isinstance(h, dict)}
        if post.get("mimeType") and "content-type" not in {k.lower() for k in headers}:
            headers["Content-Type"] = post["mimeType"]
        path_qs = (u.path or "/") + (f"?{u.query}" if u.query else "")
        size = (resp.get("content") or {}).get("size") or resp.get("bodySize") or 0
        out.append(build_flow_record(
            method=req.get("method", "GET"), scheme=u.scheme or "https", host=u.hostname,
            port=u.port or (443 if u.scheme == "https" else 80), path_qs=path_qs, req_headers=headers, body=body,
            status=resp.get("status"), resp_bytes=max(0, int(size)) if isinstance(size, (int, float)) else 0,
            ts=ts, sample_bytes=sample_bytes, store_sample=store_sample,
        ))
    return out


def import_flows(ctx, phase: str, src: Path, fmt: str, attempt_id: int, log) -> dict:
    """Copy/convert `src` into raw/ (never overwriting), register and ingest it under `attempt_id`."""
    src = Path(src)
    if not src.is_file():
        raise ClaimCheckError(f"File not found: {src}")
    short = CAPTURE_SHORT[phase]
    imports = ctx.run.artifacts_dir / "imports"
    imports.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, unique_path(imports, src.stem, src.suffix))  # keep the original untouched
    raw_path = unique_path(ctx.run.raw_dir, f"{short}_import_{attempt_id:03d}", ".jsonl")
    cfg = ctx.manifest.capture
    if fmt == "har":
        if src.stat().st_size > MAX_HAR_BYTES:
            raise ClaimCheckError(f"HAR is {src.stat().st_size // (1024 * 1024)} MB (limit {MAX_HAR_BYTES // (1024 * 1024)} MB)",
                                  hint="Export a shorter session, or convert it to claimcheck JSONL (streamed, no size limit).")
        har_stats: dict = {}
        try:
            recs = har_to_records(json.loads(src.read_text(encoding="utf-8-sig")), cfg.payload_sample_bytes, cfg.store_payload_sample, har_stats)
        except ValueError as e:
            raise ClaimCheckError(f"HAR is not valid JSON: {e}") from e
        if har_stats.get("skipped"):
            log("WARN", f"{har_stats['skipped']} malformed HAR entrie(s) skipped")
        with open(raw_path, "x", encoding="utf-8", newline="\n") as f:
            f.write(jdump({"type": "meta", "source": "har", "file": src.name}) + "\n")
            for r in recs:
                f.write(json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n")
    elif fmt == "jsonl":
        shutil.copyfile(src, raw_path)
    else:
        raise ClaimCheckError(f"Unknown format '{fmt}' (use jsonl or har)")
    rel = raw_path.relative_to(ctx.run.path).as_posix()
    ctx.store.register_raw_file(attempt_id, phase, rel)
    stats = ingest_all(ctx.store, ctx.run, final=True, log=log, attempt_id=attempt_id)
    return {"raw_file": rel, "format": fmt, "ingest": stats, "status": DONE}
