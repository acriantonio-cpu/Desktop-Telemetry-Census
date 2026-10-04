"""Claim extraction: turn marketing/README/policy text into structured, testable claims.

Rule-based on purpose (transparent, reproducible, no API cost). Each claim keeps its source sentence
so a human can judge it. Qualifiers ("unless you opt in", "by default"...) are recorded and lower the
confidence, because a qualified claim is not contradicted by traffic that the qualifier allows.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path

from claimcheck.manifest import Manifest
from claimcheck.signatures import SignatureSet
from claimcheck.util import sha256_text, truncate, unique_path

MAX_DOC_BYTES = 5 * 1024 * 1024
MAX_CLAIMS_PER_KIND = 6
FETCH_DEADLINE_S = 60.0  # wall-clock cap per document: `timeout=` only limits each socket read (slow-drip servers)
USER_AGENT = "claimcheck/0.2 (+privacy-claims research; contact via repo)"
MIN_POLICY_CHARS = 400  # a "privacy policy" shorter than this is almost surely a JS shell / cookie wall / bot check
MIN_DOC_CHARS = 120
MATCH_WINDOW = 3000  # sentences are matched up to this length (legal prose has very long sentences)
GENERIC_DISCLOSURE = "__generic_telemetry__"  # pseudo vendor: the policy admits telemetry without naming a vendor
_BOT_WALL = re.compile(
    r"just a moment|checking your browser|enable javascript|javascript is (?:required|disabled)|captcha|access denied|"
    r"attention required|verify you are (?:a )?human|are you a robot|cf-browser-verification", re.I)

CLAIM_PATTERNS: list[tuple[str, str, float]] = [
    # no_telemetry
    ("no_telemetry", r"\b(?:no|zero|without)\s+(?:any\s+)?(?:telemetry|tracking|analytics|usage (?:data|statistics|tracking)|data collection)\b", 0.85),
    ("no_telemetry", r"\b(?:does not|doesn't|do not|don't|never)\s+(?:collect|send|track|gather|report|phone home)\b[^.]{0,60}\b(?:telemetry|analytics|usage|personal data|any data|your data|tracking)", 0.80),
    ("no_telemetry", r"\btelemetry[- ]free\b", 0.9),
    ("no_telemetry", r"\bwe (?:do not|don't|never) (?:track|collect|spy)\b", 0.75),
    ("no_telemetry", r"\b(?:nessuna|zero|senza)\s+telemetria\b|\bnon (?:raccoglie|traccia|invia) (?:dati|telemetria)", 0.8),
    # local_first
    ("local_first", r"\blocal[- ]first\b|\boffline[- ]first\b", 0.85),
    ("local_first", r"\b100%\s+(?:offline|local)\b|\bruns?\s+(?:entirely |completely |fully )?(?:locally|offline)\b", 0.8),
    ("local_first", r"\b(?:data|files?|notes?|chats?|conversations?)\b[^.]{0,40}\b(?:stay|stays|never leave|never leaves|remain|remains|are stored)\b[^.]{0,40}\b(?:on your (?:device|computer|machine)|locally)", 0.8),
    ("local_first", r"\b(?:never|does not|doesn't|do not)\s+leave[s]?\s+your\s+(?:device|computer|machine)\b|\bwithout (?:it )?ever leaving your (?:device|computer)", 0.85),
    ("local_first", r"\bworks? (?:fully |completely )?(?:offline|without (?:an )?internet)\b", 0.7),
    # privacy_friendly
    ("privacy_friendly", r"\bprivacy[- ](?:friendly|first|focused|respecting|preserving|conscious|by design)\b", 0.75),
    ("privacy_friendly", r"\brespects? (?:your )?privacy\b|\byour privacy (?:is|matters)\b|\bprivate by design\b", 0.7),
    # open_source
    ("open_source", r"\bopen[- ]source\b|\bfree (?:and open[- ]source|software)\b|\bFOSS\b", 0.6),
    ("open_source", r"\b(?:MIT|GPL|AGPL|LGPL|MPL|Apache|EUPL|BSD)[- ]?(?:2\.0|3\.0|v?[23])?[- ]licen[sc]ed\b|\blicensed under (?:the )?(?:MIT|GPL|AGPL|Apache|MPL|BSD)", 0.6),
    ("open_source", r"\bauditable\b|\bcompletely (?:open|transparent)\b", 0.6),
    # no_third_party_sharing
    ("no_third_party_sharing", r"\b(?:never|do not|don't|does not|doesn't|won't|will not)\s+(?:sell|share|rent|disclose)\b[^.]{0,70}\b(?:data|information)\b", 0.8),
    ("no_third_party_sharing", r"\bno third[- ]part(?:y|ies)\b|\bwithout (?:sharing|selling) (?:your )?(?:data|information)\b", 0.75),
]
_COMPILED = [(k, re.compile(p, re.I), c) for k, p, c in CLAIM_PATTERNS]
QUALIFIERS = re.compile(
    r"\b(unless|except|only if|only when|opt[- ]in|opt[- ]out|if you (?:enable|choose|allow|agree|say yes)|optional|when enabled|by default|with your (?:consent|permission)|until you say so)\b",
    re.I,
)


_FOLD = str.maketrans({
    "\u2018": "'", "\u2019": "'", "\u201a": "'", "\u201b": "'", "\u2032": "'", "\u02bc": "'", "\u0060": "'",
    "\u201c": '"', "\u201d": '"', "\u201e": '"', "\u2033": '"',
    "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-", "\u2014": "-", "\u2212": "-", "\u00ad": "",
    "\u00a0": " ", "\u2007": " ", "\u2009": " ", "\u202f": " ", "\u200a": " ",
    "\u200b": "", "\u200c": "", "\u200d": "", "\u2060": "", "\ufeff": "",
})


def fold_typography(text: str) -> str:
    """Curly quotes, non-breaking hyphens, NBSP and zero-width characters -> plain ASCII equivalents.

    Real web pages write "don\u2019t" and "privacy\u2011friendly"; the ASCII-only patterns would miss every one of them.
    Only used for MATCHING: the stored claim sentence keeps the original characters.
    """
    return text.translate(_FOLD)


@dataclass
class LoadedDoc:
    role: str
    ref: str
    text: str = ""
    sha256: str = ""
    cache_path: str = ""
    error: str = ""
    warnings: list = field(default_factory=list)


class _TextExtractor(HTMLParser):
    BLOCK = {"p", "div", "li", "br", "h1", "h2", "h3", "h4", "h5", "h6", "tr", "section", "article", "ul", "ol", "table"}
    SKIP = {"script", "style", "noscript", "svg", "head", "template"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self._skip += 1
        elif tag in self.BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self.SKIP and self._skip:
            self._skip -= 1
        elif tag in self.BLOCK:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def html_to_text(html: str) -> str:
    p = _TextExtractor()
    try:
        p.feed(html)
        p.close()
    except Exception:  # noqa: BLE001, S110  # malformed HTML must not stop the phase  # nosec B110
        pass
    text = "".join(p.parts)
    return re.sub(r"[ \t\r\f\v]+", " ", re.sub(r"\n\s*\n+", "\n", text)).strip()


def markdown_to_text(md: str) -> str:
    md = re.sub(r"```.*?```", " ", md, flags=re.S)
    md = re.sub(r"!\[[^\]]*\]\([^)]*\)", " ", md)
    md = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", md)
    md = re.sub(r"<[^>]+>", " ", md)
    md = re.sub(r"[`*_>#]+", " ", md)
    return re.sub(r"[ \t]+", " ", md)


def _decode_body(data: bytes, ctype: str, fallback_enc: str | None) -> str:
    """UTF-8 first (what the modern web sends). `requests` alone would decode text/* without a charset as ISO-8859-1
    (RFC 2616 default) and turn every curly quote into mojibake, silently killing claim extraction."""
    m = re.search(r"charset=([\w\-]+)", ctype or "", re.I)
    for enc in ([m.group(1)] if m else []) + ["utf-8"]:
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode(fallback_enc or "latin-1", errors="replace")


def http_fetch(url: str, timeout: float = 20.0) -> tuple[str, str, bool]:
    """Return (content_type, text, truncated). Bounded in size AND in wall-clock time."""
    import requests

    if not re.match(r"^https?://", url, re.I):
        raise ValueError(f"refusing non-http(s) URL: {url}")
    t0 = time.monotonic()
    truncated = False
    with requests.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT}, stream=True) as r:
        r.raise_for_status()
        ctype = r.headers.get("content-type", "")
        chunks, size = [], 0
        for c in r.iter_content(65536):
            size += len(c)
            if size > MAX_DOC_BYTES or time.monotonic() - t0 > FETCH_DEADLINE_S:
                truncated = True
                break
            chunks.append(c)
        apparent = getattr(r, "apparent_encoding", None) if chunks else None
    return ctype, _decode_body(b"".join(chunks), ctype, apparent), truncated


def _normalize(ctype: str, body: str) -> str:
    if "html" in ctype.lower() or body.lstrip()[:15].lower().startswith(("<!doctype", "<html")):
        return html_to_text(body)
    return markdown_to_text(body)


def load_documents(
    manifest: Manifest, docs_dir: Path, log: Callable[[str, str], None], fetch: Callable[[str], tuple] | None = None
) -> list[LoadedDoc]:
    """Load all documents listed in the manifest (+ the repo README if none given). Failures are non-fatal."""
    fetch = fetch or http_fetch
    entries = [(d.type, d.location, d.role) for d in manifest.sources.documents]
    repo = Path(manifest.sources.repo_path) if manifest.sources.repo_path else None
    if repo and repo.is_dir() and not any(r == "readme" for _, _, r in entries):
        for cand in sorted(repo.glob("README*")):
            if cand.is_file():
                entries.append(("file", str(cand), "readme"))
                break
    out: list[LoadedDoc] = []
    for typ, loc, role in entries:
        doc = LoadedDoc(role=role, ref=loc)
        try:
            if typ == "url":
                res = fetch(loc)
                ctype, body = res[0], res[1]
                if len(res) > 2 and res[2]:
                    doc.warnings.append("document truncated (size or time limit): later parts were not read")
                doc.text = _normalize(ctype, body)
            else:
                p = Path(loc)
                if p.stat().st_size > MAX_DOC_BYTES:
                    raise ValueError("file larger than 5 MB")
                raw = p.read_bytes()
                if b"\x00" in raw[:4096] and not raw.startswith((b"\xff\xfe", b"\xfe\xff")):
                    raise ValueError("binary file (PDF/Office?): export the policy as .md/.txt/.html")
                body = _read_text_bytes(raw)
                doc.text = html_to_text(body) if p.suffix.lower() in (".html", ".htm") else markdown_to_text(body)
            doc.warnings += _sanity_warnings(doc.text, role)
            doc.sha256 = sha256_text(doc.text)
            cache = unique_path(docs_dir, f"{role}-{doc.sha256[:10]}", ".txt")
            cache.write_text(doc.text, encoding="utf-8", newline="\n")
            doc.cache_path = str(cache)
            log("VERBOSE", f"document loaded [{role}] {loc} ({len(doc.text)} chars)")
            for w in doc.warnings:
                log("WARN", f"[{role}] {loc}: {w}")
        except Exception as e:  # noqa: BLE001
            doc.error = f"{type(e).__name__}: {e}"
            log("WARN", f"could not load [{role}] {loc}: {doc.error}")
        out.append(doc)
    return out


def _read_text_bytes(raw: bytes) -> str:
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace")
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    return raw.decode("utf-8", errors="replace")


def _sanity_warnings(text: str, role: str) -> list[str]:
    """Signals that a document is not really the document: silent 'no claims' would otherwise look like 'no promises'."""
    out = []
    n = len(text.strip())
    if n < MIN_DOC_CHARS:
        out.append(f"only {n} characters of text: page probably rendered by JavaScript (not supported), empty, or behind a login")
    elif n < 2500 and _BOT_WALL.search(text):
        out.append("looks like a bot-check / cookie-wall / 'enable JavaScript' page, not the real document")
    elif role == "privacy_policy" and n < MIN_POLICY_CHARS:
        out.append(f"privacy policy has only {n} characters: too short to be trusted (JS shell? cookie wall?)")
    return out


def is_usable_policy(doc: LoadedDoc) -> bool:
    """A policy counts for disclosure checks only if it really looks like one (see _sanity_warnings)."""
    return doc.role == "privacy_policy" and bool(doc.text) and not _sanity_warnings(doc.text, "privacy_policy")


def split_sentences(text: str) -> list[str]:
    """Sentences for matching. Long legal sentences are kept whole (up to MATCH_WINDOW chars, then windowed with overlap)."""
    parts = re.split(r"(?<=[.!?])\s+|\n+", text)
    out = []
    for p in parts:
        p = re.sub(r"^[\s\-*\u2022]+", "", p).strip()
        if len(p) < 8:
            continue
        if len(p) <= MATCH_WINDOW:
            out.append(p)
        else:  # minified / punctuation-less blobs: overlapping windows so a claim is never cut in half
            step = MATCH_WINDOW - 300
            out.extend(p[i:i + MATCH_WINDOW] for i in range(0, len(p), step))
    return out


def _snippet(sent: str, start: int, end: int, width: int = 400) -> str:
    """Show the sentence; if it is long, show the part around the match (the reader must see WHY it matched)."""
    if len(sent) <= width:
        return sent
    a = max(0, start - width // 3)
    b = min(len(sent), a + width)
    return ("..." if a > 0 else "") + sent[a:b].strip() + ("..." if b < len(sent) else "")


_NEG_BEFORE = re.compile(
    r"(?:\b(?:not|never|no longer|isn't|aren't|wasn't|weren't|cannot|can't|hardly|far from|anything but|neither|nor|"
    r"rather than|instead of|unlike|as opposed to|whereas|nothing like)\b|\bnon|\bun)[- ]?(?:\w+[- ]+){0,2}$", re.I)
_NEG_GUARD_KINDS = {"privacy_friendly", "open_source", "local_first"}


def _negated_before(folded: str, start: int) -> bool:
    return bool(_NEG_BEFORE.search(folded[max(0, start - 40):start]))


def extract_claims(docs: list[LoadedDoc]) -> list[dict]:
    """Return claim dicts (kind, text, source_role, source_ref, confidence, detail). Deduplicated, capped per kind."""
    found: dict[str, dict[str, dict]] = {}
    for doc in docs:
        if not doc.text:
            continue
        for sent in split_sentences(doc.text):
            if sent.rstrip().endswith("?"):  # FAQ headings ("Is it open source?") are questions, not promises
                continue
            folded = fold_typography(sent)
            for kind, rx, base in _COMPILED:
                m = rx.search(folded)
                if not m:
                    continue
                if kind in _NEG_GUARD_KINDS and _negated_before(folded, m.start()):
                    continue  # "this app is NOT open source" must never become an open_source claim
                quals = sorted({q.lower() for q in QUALIFIERS.findall(folded)})
                conf = max(0.3, base - (0.15 if quals else 0.0))
                key = re.sub(r"\W+", " ", folded.lower()).strip()[:600]
                slot = found.setdefault(kind, {})
                prev = slot.get(key)
                if prev is None or conf > prev["confidence"]:
                    slot[key] = {
                        "kind": kind, "text": _snippet(sent, m.start(), m.end()), "source_role": doc.role, "source_ref": doc.ref,
                        "confidence": round(conf, 2), "detail": {"match": m.group(0), "qualifiers": quals},
                    }
    out = []
    for slot in found.values():
        ranked = sorted(slot.values(), key=lambda c: (-c["confidence"], len(c["text"])))
        out.extend(ranked[:MAX_CLAIMS_PER_KIND])
    return out


_NEG_NEAR = re.compile(
    r"\b(?:not|never|no|without|neither|nor|avoid(?:s|ed)?|free of|don't|doesn't|do not|does not|won't|will not|isn't|aren't|"
    r"opt(?:ed)? out of|disable[sd]?|block(?:s|ed)?|refrain(?:s)? from)\b[^.;!?\n]{0,45}$", re.I)
_CONTRAST = re.compile(r"\b(?:but|however|although|though|except|yet|while|whereas)\b|[;:]", re.I)
_GENERIC_TERMS = re.compile(
    r"\b(?:telemetry|analytics|usage (?:data|statistics|information|metrics)|diagnostic(?:s| data| information)|"
    r"crash (?:reports?|data|logs?)|error reports?|performance data)\b", re.I)
_COLLECT_VERBS = re.compile(r"\b(?:collect|gather|record|receive|send|transmit|log|use|share|process|store|report)s?\b|\bcollection\b", re.I)


def _negated_mention(folded_low: str, start: int) -> bool:
    """True if the mention at `start` sits in a negated clause: 'we do NOT use <vendor>', 'no <vendor>', 'without <vendor>'."""
    sent_start = max(folded_low.rfind(c, 0, start) for c in ".!?\n") + 1
    before = folded_low[sent_start:start]
    m = _NEG_NEAR.search(before)
    if not m:
        return False
    between = before[m.end() - len(m.group(0)):]
    return not _CONTRAST.search(between)  # "we do not sell data BUT use Sentry" -> Sentry is disclosed


def extract_disclosed_vendors(docs: list[LoadedDoc], sigs: SignatureSet) -> list[dict]:
    """Which telemetry vendors does the *privacy policy* admit to? (role == privacy_policy only).

    A mention only counts if it is not negated ("we do NOT use Google Analytics" is the opposite of a disclosure).
    A `__generic_telemetry__` pseudo-vendor is added when the policy admits telemetry/analytics/crash reports in general.
    """
    out, seen = [], set()
    for doc in docs:
        if doc.role != "privacy_policy" or not doc.text:
            continue
        folded = fold_typography(doc.text)
        low = folded.lower()
        for v in sigs.vendors.values():
            terms = [n for n in (v.policy_names or []) if len(n) >= 4] + [d for d in v.domains if len(d) >= 8]
            for t in terms:
                if (v.id, doc.ref) in seen:
                    break
                for m in re.finditer(r"(?<![A-Za-z0-9])" + re.escape(t.lower()) + r"(?![A-Za-z0-9])", low):
                    if _negated_mention(low, m.start()):
                        continue
                    seen.add((v.id, doc.ref))
                    s = max(0, m.start() - 60)
                    out.append({"sdk_id": v.id, "source_ref": doc.ref, "snippet": truncate(doc.text[s : m.end() + 60].replace("\n", " "), 200)})
                    break
        if (GENERIC_DISCLOSURE, doc.ref) not in seen:
            for sent in split_sentences(folded):
                m = _GENERIC_TERMS.search(sent)
                if m and _COLLECT_VERBS.search(sent) and not _negated_mention(sent.lower(), m.start()):
                    seen.add((GENERIC_DISCLOSURE, doc.ref))
                    out.append({"sdk_id": GENERIC_DISCLOSURE, "source_ref": doc.ref, "snippet": truncate(sent, 200)})
                    break
    return out
