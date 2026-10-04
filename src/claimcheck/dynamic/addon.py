"""mitmproxy addon: writes one JSON line per observed connection/request to a JSONL file.

IMPORTANT DESIGN CONSTRAINT: this file is loaded by `mitmdump -s addon.py`, possibly by a *different
Python* than the one running claimcheck (e.g. the standalone mitmproxy installer on Windows).
Therefore it must stay SELF-CONTAINED: standard library + mitmproxy only, no `claimcheck` imports.

Privacy by design: we record structure (JSON key names, query-parameter names, hashed identifiers,
sizes, timings), and only a small *redacted* body sample. Raw identifiers are never stored: UUID-like
values are replaced by a short SHA-1 prefix so that "the same identifier is sent repeatedly" stays
detectable without keeping the identifier itself.

Record types written (field `type`): meta | flow | sni | tls_failed | error
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
import time
import zlib
from urllib.parse import parse_qs, urlsplit

try:  # imported lazily so that unit tests can import this module without mitmproxy installed
    from mitmproxy import http  # type: ignore
except Exception:  # noqa: BLE001
    http = None  # type: ignore

ADDON_VERSION = "1"
MAX_PARSE_BYTES = 256 * 1024
MAX_KEYS = 80
MAX_IDS = 10
MAX_OTHER_ENC_BYTES = 32 * 1024  # br/zstd/...: only decoded (by mitmproxy) when the COMPRESSED body is this small
MAX_KEY_LEN = 80
MAX_PATH_LEN = 300

_UUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_HEX = re.compile(r"\b(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\b")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_LONGTOKEN = re.compile(r"[A-Za-z0-9_\-+/=]{32,}")
_LONGNUM = re.compile(r"\b\d{9,}\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]*")
_AUTHHDR = re.compile(r"\b(bearer|basic)\s+[A-Za-z0-9._~+/\-]{8,}=*", re.I)
_URLCRED = re.compile(r"(?<=://)[^/\s:@]+:[^/\s@]+(?=@)")
_APIKEY = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\b(?:sk|pk|rk|ghp|gho|ghs|glpat|xox[abprs]|AIza)[-_][A-Za-z0-9_\-]{16,}")
_WINUSER = re.compile(r"(?i)\b([A-Z]:\\+Users\\+)[^\\/\s\"'<>|:*?]+")
_NIXUSER = re.compile(r"(/(?:home|Users)/)[^/\s\"'<>]+")
_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")


def redact(text: str) -> str:
    """Keep in sync with claimcheck.util.redact_text (a unit test enforces equality)."""
    text = _JWT.sub("<jwt>", text)
    text = _AUTHHDR.sub(lambda m: m.group(1) + " <token>", text)
    text = _URLCRED.sub("<cred>", text)
    text = _EMAIL.sub("<email>", text)
    text = _UUID.sub("<uuid>", text)
    text = _APIKEY.sub("<key>", text)
    text = _WINUSER.sub(lambda m: m.group(1) + "<user>", text)
    text = _NIXUSER.sub(lambda m: m.group(1) + "<user>", text)
    text = _MAC.sub("<mac>", text)
    text = _IPV4.sub("<ip>", text)
    text = _LONGTOKEN.sub("<token>", text)
    return _LONGNUM.sub("<num>", text)


def safe_key(k) -> str:
    """Key/parameter NAMES can carry identifiers too ({"<uuid>": ...}, {"a@b.com": ...}): redact and cap them."""
    return redact(str(k))[:MAX_KEY_LEN]


def decode_body(raw: bytes | None, encoding: str, fallback=None, limit: int = MAX_PARSE_BYTES) -> tuple[bytes, bool, str]:
    """Bounded body decoding -> (bytes, complete, note).

    The app under test is untrusted software: a 1 MB gzip body may expand to gigabytes. We therefore stream-decompress
    gzip/deflate up to `limit` bytes only; other encodings are handed to `fallback` (mitmproxy's own decoder) only
    when the compressed body is tiny. `complete=False` means the returned bytes are a prefix.
    """
    if not raw:
        return b"", True, ""
    enc = (encoding or "").strip().lower()
    if enc in ("", "identity"):
        return raw, True, ""
    if enc in ("gzip", "x-gzip", "deflate"):
        for wbits in (zlib.MAX_WBITS | 32, -zlib.MAX_WBITS):  # zlib/gzip auto-detect, then raw deflate
            d = zlib.decompressobj(wbits)
            try:
                out = d.decompress(raw, limit + 1)
            except zlib.error:
                continue
            if len(out) > limit or d.unconsumed_tail:
                return out[:limit], False, "body truncated: decompression capped"
            return out, True, ""
        return b"", False, "body not decodable (corrupt gzip/deflate)"
    if fallback is not None and len(raw) <= MAX_OTHER_ENC_BYTES:
        try:
            got = fallback()
            if got is not None:
                return got[:limit] if len(got) > limit else got, len(got) <= limit, ""
        except Exception:  # noqa: BLE001, S110  # undecodable body: we still record sizes/hosts  # nosec B110
            pass
    return b"", False, f"body not decoded (content-encoding {enc[:20]})"


def id_hash(value: str) -> str:
    return hashlib.sha256(value.lower().encode("utf-8", "replace")).hexdigest()[:12]


def flatten_keys(obj, prefix: str = "", depth: int = 0, out: list | None = None) -> list:
    """Key names of a JSON structure (dotted, depth <= 3, arrays collapsed to '[]'). Values are NOT kept."""
    if out is None:
        out = []
    if len(out) >= MAX_KEYS or depth > 3:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{safe_key(k)}" if prefix else safe_key(k)
            if path not in out and len(out) < MAX_KEYS:
                out.append(path)
            flatten_keys(v, path, depth + 1, out)
    elif isinstance(obj, list):
        for item in obj[:5]:
            flatten_keys(item, prefix + "[]", depth + 1, out)
    return out


def analyse_body(body: bytes | None, content_type: str) -> dict:
    """Extract structure/features from a request body. Never raises."""
    res = {"keys": [], "ids": [], "is_json": False, "is_form": False, "binary": False, "text": ""}
    if not body:
        return res
    head = body[:MAX_PARSE_BYTES]
    ct = (content_type or "").lower()
    try:
        text = head.decode("utf-8")
    except UnicodeDecodeError:
        res["binary"] = True
        text = head.decode("latin-1")
    if res["binary"] and "json" not in ct:
        # binary payload (protobuf, minidump, compressed...): only look for printable id patterns
        text = "".join(ch if 32 <= ord(ch) < 127 else " " for ch in text[:4096])
    else:
        s = text.lstrip()
        if "json" in ct or s[:1] in ("{", "["):
            try:
                res["keys"] = flatten_keys(json.loads(text))
                res["is_json"] = True
            except ValueError:
                pass
        elif "x-www-form-urlencoded" in ct:
            try:
                res["keys"] = sorted({safe_key(k) for k in parse_qs(text, keep_blank_values=True)})[:MAX_KEYS]
                res["is_form"] = True
            except ValueError:
                pass
    ids = {id_hash(m) for m in _UUID.findall(text)} | {id_hash(m) for m in _HEX.findall(text)}
    res["ids"] = sorted(ids)[:MAX_IDS]
    res["text"] = text
    return res


def build_flow_record(
    *, method: str, scheme: str, host: str, port: int, path_qs: str, req_headers: dict, body: bytes | None,
    status: int | None, resp_bytes: int | None, ts: float, sni: str = "", sample_bytes: int = 512,
    store_sample: bool = True, kind: str = "http", error: str = "", wire_bytes: int | None = None, body_note: str = "",
) -> dict:
    """Pure function (no mitmproxy objects) so it is unit-testable and reusable by the HAR importer."""
    parts = urlsplit(path_qs)
    query = parse_qs(parts.query, keep_blank_values=True)
    hdr = {str(k).lower(): str(v) for k, v in (req_headers or {}).items()}
    ct = hdr.get("content-type", "")
    info = analyse_body(body, ct)
    qids = sorted({id_hash(m) for vals in query.values() for v in vals for m in _UUID.findall(v)})
    ids = sorted(set(info["ids"]) | set(qids))[:MAX_IDS]
    sample = ""
    if store_sample and sample_bytes > 0 and info["text"] and not info["binary"]:
        sample = redact(info["text"][:sample_bytes])
    rec = {
        "type": "flow" if kind == "http" else kind,
        "ts": ts, "host": (host or "").lower().rstrip("."), "sni": (sni or "").lower(), "port": port, "scheme": scheme,
        # identifiers can hide in the path ("/users/<email>/track/123456789") and in key NAMES: redact both
        "method": method, "path": redact(parts.path or "/")[:MAX_PATH_LEN],
        "query_keys": sorted({safe_key(k) for k in query})[:30], "status": status,
        "req_bytes": wire_bytes if wire_bytes is not None else (len(body) if body else 0),
        "resp_bytes": resp_bytes or 0, "req_ct": ct.split(";")[0].strip(),
        "payload_keys": info["keys"], "id_hashes": ids, "sample": sample,
        "features": {
            "is_json": info["is_json"], "is_form": info["is_form"], "binary": info["binary"],
            "n_keys": len(info["keys"]), "has_uuid": bool(ids),
            "has_auth": "authorization" in hdr, "has_cookie": "cookie" in hdr,
            "content_encoding": hdr.get("content-encoding", ""), "user_agent": redact(hdr.get("user-agent", "")[:120]),
        },
    }
    if body_note:
        rec["features"]["body_note"] = body_note
    if error:
        rec["error"] = error[:300]
    return rec


class ClaimCheckAddon:
    """mitmproxy addon object. Every hook is wrapped: an addon bug must never break the user's capture."""

    MAX_ERROR_RECORDS = 20

    def __init__(self) -> None:
        self.fh = None
        self.lines = 0
        self.errors = 0

    def _note_error(self, where: str, exc: Exception) -> None:
        """Never raise into mitmproxy, but never be silent either: leave a trace in the JSONL (first N only)."""
        self.errors += 1
        if self.errors <= self.MAX_ERROR_RECORDS:
            try:
                self._write({"type": "addon_error", "ts": time.time(), "where": where, "error": f"{type(exc).__name__}: {exc}"[:300]})
            except Exception:  # noqa: BLE001, S110  # last resort: the trace itself failed  # nosec B110
                pass

    # ---- options / lifecycle --------------------------------------------
    def load(self, loader):
        loader.add_option("claimcheck_out", str, "", "claimcheck: output JSONL path")
        loader.add_option("claimcheck_sample_bytes", int, 512, "claimcheck: body sample bytes (0=none)")
        loader.add_option("claimcheck_store_sample", bool, True, "claimcheck: store redacted body sample")
        loader.add_option("claimcheck_canary_suffix", str, "", "claimcheck: comma-separated host suffixes answered locally (canary)")

    def _opt(self, name, default=None):
        from mitmproxy import ctx  # type: ignore

        return getattr(ctx.options, name, default)

    def running(self):
        out = self._opt("claimcheck_out", "")
        if not out:
            return
        # append mode: a resumed/rerun capture never truncates earlier data
        try:
            self.fh = open(out, "a", encoding="utf-8", newline="\n")  # noqa: SIM115
        except OSError as e:
            # Say it loudly (mitmdump log) - claimcheck aborts the capture when no 'meta' line ever appears.
            raise RuntimeError(f"claimcheck addon cannot open its output file {out!r}: {e}") from e
        try:
            from mitmproxy import version  # type: ignore

            mv = version.VERSION
        except Exception:  # noqa: BLE001
            mv = "?"
        self._write({"type": "meta", "addon_version": ADDON_VERSION, "mitmproxy": mv, "started_at": time.time()})

    def done(self):
        if self.fh:
            self.fh.flush()
            self.fh.close()
            self.fh = None

    def _write(self, rec: dict) -> None:
        if not self.fh:
            return
        self.fh.write(json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n")
        self.fh.flush()
        self.lines += 1

    # ---- TLS (works even when the app pins certificates) ------------------
    def tls_clienthello(self, data):
        try:
            sni = data.client_hello.sni or ""
            peer = getattr(data.context.server, "address", None) or ("", 0)
            self._write({"type": "sni", "ts": time.time(), "host": sni or str(peer[0]), "sni": sni, "port": peer[1]})
        except Exception as e:  # noqa: BLE001
            self._note_error("tls_clienthello", e)

    def tls_failed_client(self, data):
        try:
            conn = data.conn
            srv = getattr(data.context, "server", None)
            addr = getattr(srv, "address", None) or ("", 0)
            host = getattr(conn, "sni", None) or (addr[0] if addr else "")
            self._write({"type": "tls_failed", "ts": time.time(), "host": str(host), "sni": str(getattr(conn, "sni", "") or ""),
                         "port": addr[1] if addr else 0, "error": str(getattr(conn, "error", ""))[:300]})
        except Exception as e:  # noqa: BLE001
            self._note_error("tls_failed_client", e)

    # ---- HTTP -------------------------------------------------------------
    def request(self, flow):
        try:
            suffixes = [s.strip().lower() for s in (self._opt("claimcheck_canary_suffix", "") or "").split(",") if s.strip()]
            host = flow.request.pretty_host.lower()
            if suffixes and any(host == s or host.endswith("." + s) for s in suffixes):
                flow.response = http.Response.make(200, b'{"ok":true}', {"Content-Type": "application/json"})
        except Exception as e:  # noqa: BLE001
            self._note_error("request", e)

    def _record(self, flow, kind="http", error=""):
        req = flow.request
        hdrs = dict(req.headers.items())
        enc = next((v for k, v in hdrs.items() if str(k).lower() == "content-encoding"), "")
        raw = getattr(req, "raw_content", None)
        if raw is None:  # minimal request object (tests / very old mitmproxy): legacy, unbounded path
            body, complete, note, raw = req.get_content(strict=False) or b"", True, "", b""
        else:
            body, complete, note = decode_body(raw, str(enc), fallback=lambda: req.get_content(strict=False))
        resp = flow.response
        rb = 0
        if resp is not None:
            with contextlib.suppress(Exception):
                rb = len(resp.raw_content or b"")
        sni = ""
        with contextlib.suppress(Exception):
            sni = flow.client_conn.sni or ""
        rec = build_flow_record(
            method=req.method, scheme=req.scheme, host=req.pretty_host, port=req.port, path_qs=req.path,
            req_headers=hdrs, body=body, status=resp.status_code if resp else None,
            resp_bytes=rb, ts=req.timestamp_start or time.time(), sni=sni,
            sample_bytes=int(self._opt("claimcheck_sample_bytes", 512) or 0),
            store_sample=bool(self._opt("claimcheck_store_sample", True)), kind=kind, error=error,
            # decoded size when we saw the whole body, otherwise the on-the-wire size (a lower bound, never 0)
            wire_bytes=len(body) if complete else len(raw), body_note=note,
        )
        self._write(rec)

    def response(self, flow):
        try:
            self._record(flow)
        except Exception as e:  # noqa: BLE001
            self._note_error("response", e)

    def error(self, flow):
        try:
            self._record(flow, kind="error", error=str(flow.error.msg) if flow.error else "error")
        except Exception as e:  # noqa: BLE001
            self._note_error("error", e)


addons = [ClaimCheckAddon()]
