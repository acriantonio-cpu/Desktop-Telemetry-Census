"""Shared test helpers (importable from test modules)."""

from __future__ import annotations

import json
import struct
from pathlib import Path


def build_asar(files: dict[str, bytes]) -> bytes:
    """Build a minimal valid Electron asar archive in memory."""
    header: dict = {"files": {}}
    data = b""
    for path, content in files.items():
        node = header
        parts = path.split("/")
        for d in parts[:-1]:
            node = node["files"].setdefault(d, {"files": {}})
        node["files"][parts[-1]] = {"size": len(content), "offset": str(len(data))}
        data += content
    j = json.dumps(header).encode()
    pad = (4 - len(j) % 4) % 4
    payload = struct.pack("<I", len(j)) + j + b"\0" * pad
    hdr_pickle = struct.pack("<I", len(payload)) + payload
    return struct.pack("<I", 4) + struct.pack("<I", len(hdr_pickle)) + hdr_pickle + data


def write_manifest(path: Path, **overrides) -> Path:
    import yaml

    data = {
        "schema_version": 1,
        "app": {"name": "TestApp", "exe_name": "testapp.exe"},
        "first_party_domains": ["testapp.test"],
        "classify": {"resolve_cname": False},
    }
    for k, v in overrides.items():
        if isinstance(v, dict) and isinstance(data.get(k), dict):
            data[k].update(v)
        else:
            data[k] = v
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def telemetry_flows(n: int = 6, host: str = "eu.i.posthog.com", phase: str = "capture_idle", t0: float = 1000.0) -> list[dict]:
    return [
        {"capture_phase": phase, "host": host, "kind": "http", "method": "POST", "path": "/capture/", "ts": t0 + i * 30.0,
         "req_bytes": 400 + i, "payload_keys": ["event", "distinct_id", "properties"], "id_hashes": ["abc123"]}
        for i in range(n)
    ]


def jsonl_flow(host: str = "eu.i.posthog.com", ts: float = 1.0, **kw) -> dict:
    rec = {"type": "flow", "ts": ts, "host": host, "sni": host, "port": 443, "scheme": "https", "method": "POST",
           "path": "/capture/", "query_keys": [], "status": 200, "req_bytes": 100, "resp_bytes": 2, "req_ct": "application/json",
           "payload_keys": ["event", "distinct_id", "properties"], "id_hashes": ["abc123"], "sample": "{}", "features": {}}
    rec.update(kw)
    return rec


def http_record(**kw) -> dict:
    """A realistic 'flow' record as written by the addon (used by the ingest tests)."""
    rec = {"type": "flow", "ts": 1000.0, "host": "eu.i.posthog.com", "sni": "eu.i.posthog.com", "port": 443, "scheme": "https",
           "method": "POST", "path": "/capture/", "query_keys": ["v"], "status": 200, "req_bytes": 300, "resp_bytes": 2,
           "req_ct": "application/json", "payload_keys": ["event", "distinct_id", "properties"], "id_hashes": ["abc123def456"],
           "sample": "{}", "features": {}}
    rec.update(kw)
    return rec
