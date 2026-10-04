"""Ingest raw JSONL capture files into the store. Idempotent (UNIQUE(raw_file_id, raw_line)) and resumable."""

from __future__ import annotations

import json
import math
from collections.abc import Callable, Iterator
from pathlib import Path

from claimcheck.runs import RunDir
from claimcheck.store import Store
from claimcheck.util import sha256_file

KIND_MAP = {"flow": "http", "error": "error", "sni": "sni", "tls_failed": "tls_failed"}
BATCH = 2000
MAX_LINE_BYTES = 4 * 1024 * 1024  # a genuine record is a few KB; anything larger is corrupt/hostile and is skipped, not loaded in RAM
MAX_TEXT = {"host": 255, "sni": 255, "path": 300, "sample": 4000, "req_ct": 120, "method": 16, "scheme": 16}


def _f(v) -> float:
    """Finite float or 0.0 (NaN/inf would poison sorting and interval statistics)."""
    try:
        x = float(v)
    except (TypeError, ValueError):
        return 0.0
    return x if math.isfinite(x) else 0.0


def _i(v) -> int:
    if isinstance(v, bool):
        return 0
    try:
        x = float(v)
    except (TypeError, ValueError):
        return 0
    return int(x) if math.isfinite(x) and 0 <= x < 2**62 else 0


def _s(v, key: str = "") -> str:
    return v[: MAX_TEXT.get(key, 255)] if isinstance(v, str) else ""


def _strs(v, cap: int = 100) -> list[str]:
    return [x[:120] for x in v if isinstance(x, str)][:cap] if isinstance(v, list) else []


def record_to_row(rec: dict, attempt_id: int, raw_id: int, line_no: int, phase: str) -> dict | None:
    """One JSONL record -> one `flows` row. Imported/foreign files may hold ANY JSON: every field is coerced, never trusted."""
    kind = KIND_MAP.get(rec.get("type", ""))
    if not kind:
        return None
    feats = dict(rec["features"]) if isinstance(rec.get("features"), dict) else {}
    if isinstance(rec.get("error"), str) and rec["error"]:
        feats["error"] = rec["error"][:300]
    host = _s(rec.get("host"), "host") or _s(rec.get("sni"), "sni")
    return {
        "attempt_id": attempt_id, "raw_file_id": raw_id, "raw_line": line_no, "capture_phase": phase,
        "ts": _f(rec.get("ts")), "kind": kind, "host": host.lower(),
        "sni": _s(rec.get("sni"), "sni"), "port": _i(rec.get("port")) or None, "scheme": _s(rec.get("scheme"), "scheme"),
        "method": _s(rec.get("method"), "method"), "path": _s(rec.get("path"), "path"), "query_keys": _strs(rec.get("query_keys"), 30),
        "status_code": _i(rec.get("status")) or None, "req_bytes": _i(rec.get("req_bytes")), "resp_bytes": _i(rec.get("resp_bytes")),
        "req_ct": _s(rec.get("req_ct"), "req_ct"), "payload_keys": _strs(rec.get("payload_keys"), 80),
        "id_hashes": _strs(rec.get("id_hashes"), 10), "sample": _s(rec.get("sample"), "sample"), "features": feats,
    }


def _iter_lines(fh) -> Iterator[tuple[bytes | None, bool]]:
    """(line, terminated). An oversized line is drained in chunks and yielded as None: bounded RAM whatever the file holds."""
    while True:
        line = fh.readline(MAX_LINE_BYTES + 1)
        if not line:
            return
        if len(line) > MAX_LINE_BYTES and not line.endswith(b"\n"):
            terminated = False
            while True:
                rest = fh.readline(1 << 20)
                if not rest:
                    break
                if rest.endswith(b"\n"):
                    terminated = True
                    break
            yield None, terminated
        else:
            yield line, line.endswith(b"\n")


def ingest_raw_file(store: Store, run: RunDir, raw: dict, final: bool, log: Callable[[str, str], None]) -> dict:
    """Ingest lines not yet ingested (streaming: bounded RAM). `final=True` = writer finished (torn last line dropped)."""
    stats = {"file": raw["path"], "lines": 0, "inserted": 0, "meta": 0, "bad": 0, "torn": 0, "addon_errors": 0}
    base = run.path.resolve()
    path = (run.path / raw["path"]).resolve()
    if not path.is_relative_to(base):  # a shared/hostile run could point outside its own folder
        log("WARN", f"refusing raw file outside the run folder: {raw['path']}")
        return stats
    if not path.exists():
        log("WARN", f"raw file missing: {raw['path']}")
        return stats
    start = int(raw["lines_ingested"])
    rows: list[dict] = []
    consumed = start
    with open(path, "rb") as fh:
        for idx, (line, terminated) in enumerate(_iter_lines(fh)):
            if idx < start:
                continue
            line_no = idx + 1
            if line is None:
                stats["bad"] += 1
                consumed = idx + 1
                log("WARN", f"{raw['path']}:{line_no}: line larger than {MAX_LINE_BYTES // (1024 * 1024)} MB skipped")
                continue
            body = line.strip()
            if not body:
                consumed = idx + 1
                continue
            try:
                rec = json.loads(body.decode("utf-8"))
                if not isinstance(rec, dict):
                    raise ValueError("not an object")
            except (ValueError, UnicodeDecodeError):
                if not terminated and not final:
                    break  # writer may still be appending this line: retry later
                stats["torn" if not terminated else "bad"] += 1
                consumed = idx + 1
                log("WARN", f"{raw['path']}:{line_no}: unreadable line skipped")
                continue
            consumed = idx + 1
            stats["lines"] += 1
            if rec.get("type") == "addon_error":
                stats["addon_errors"] += 1
                if stats["addon_errors"] <= 5:
                    log("WARN", f"addon error in {rec.get('where')}: {rec.get('error')}")
            try:
                row = record_to_row(rec, raw["attempt_id"], raw["id"], line_no, raw["capture_phase"])
            except Exception as e:  # noqa: BLE001  # one weird record must never abort the whole ingest
                stats["bad"] += 1
                log("WARN", f"{raw['path']}:{line_no}: record skipped ({type(e).__name__})")
                continue
            if row is None:
                stats["meta"] += 1
                continue
            rows.append(row)
            if len(rows) >= BATCH:
                stats["inserted"] += store.insert_many("flows", rows, ignore_dups=True)
                rows = []
    stats["inserted"] += store.insert_many("flows", rows, ignore_dups=True)
    store.update_raw_file(raw["id"], sha256=sha256_file(path), size=path.stat().st_size,
                          lines_ingested=consumed, complete=1 if final else 0)
    return stats


def ingest_all(store: Store, run: RunDir, final: bool, log: Callable[[str, str], None], attempt_id: int | None = None) -> list[dict]:
    """Ingest every raw file that is not complete yet (or only those of one attempt)."""
    out = []
    for raw in store.raw_files(attempt_id=attempt_id, only_incomplete=True):
        out.append(ingest_raw_file(store, run, raw, final, log))
    return out


def count_lines_fast(path: Path, offset: int = 0) -> tuple[int, int]:
    """(new_newlines, new_offset) since `offset` - used by the capture heartbeat."""
    try:
        with open(path, "rb") as f:
            f.seek(offset)
            chunk = f.read()
        return chunk.count(b"\n"), offset + len(chunk)
    except OSError:
        return 0, offset


def verify_raw_files(store: Store, run: RunDir) -> list[dict]:
    """Recompute the SHA-256 of every completed raw file and compare it with the value recorded at ingest time.

    status: ok | changed (modified after ingest: corruption or tampering) | missing | not-complete (still being ingested).
    """
    out = []
    base = run.path.resolve()
    for raw in store.raw_files():
        path = (run.path / raw["path"]).resolve()
        row = {"file": raw["path"], "status": "", "expected": raw.get("sha256") or "", "actual": ""}
        if not path.is_relative_to(base) or not path.exists():
            row["status"] = "missing"
        elif not raw.get("complete"):
            row["status"] = "not-complete"
        else:
            row["actual"] = sha256_file(path)
            row["status"] = "ok" if row["actual"] == row["expected"] else "changed"
        out.append(row)
    return out
