"""Small, dependency-light helpers used everywhere."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path

# Public-suffix approximation: enough to find the "registrable domain" without an external list.
# Limitation (documented): unusual suffixes not listed here are treated as single-label TLDs.
_MULTI_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "org.au", "co.nz",
    "co.jp", "ne.jp", "or.jp", "com.br", "com.cn", "com.mx", "com.tr", "com.sg", "com.hk",
    "co.in", "co.kr", "co.za", "com.ar", "com.tw", "com.ua", "com.pl", "co.il", "github.io",
    "gitlab.io", "pages.dev", "netlify.app", "vercel.app", "herokuapp.com", "web.app",
    "firebaseapp.com", "cloudfront.net", "azurewebsites.net", "appspot.com",
}
# Cloud / shared-hosting parents: every customer shares the parent, so the "registrable domain" of a host under
# one of these is the host ITSELF. Otherwise a first-party entry like "myapp.s3.amazonaws.com" would make ALL of
# AWS look first-party (a silent false negative for third-party trackers hosted there).
_HOST_EXACT = {
    "amazonaws.com", "windows.net", "cloudfront.net", "azureedge.net", "azurefd.net", "trafficmanager.net",
    "cloudapp.azure.com", "googleusercontent.com", "elasticbeanstalk.com", "workers.dev", "fly.dev",
    "onrender.com", "railway.app", "run.app", "cloudfunctions.net", "ondigitalocean.app", "digitaloceanspaces.com",
    "netlify.com", "surge.sh", "glitch.me", "repl.co", "replit.app", "ngrok.io", "ngrok-free.app",
    "trycloudflare.com", "pythonanywhere.com", "supabase.co", "fastly.net", "b-cdn.net", "akamaized.net",
    "edgekey.net", "github.io", "gitlab.io", "pages.dev", "netlify.app", "vercel.app", "herokuapp.com", "web.app",
    "firebaseapp.com", "azurewebsites.net", "appspot.com",
}
_COUNTRY_SUFFIXES = _MULTI_SUFFIXES - _HOST_EXACT


def utcnow_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


_WIN_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
SLUG_MAX = 64


def slugify(name: str) -> str:
    """Filesystem-safe folder name. Accents are transliterated; names with no ASCII at all get a stable hash
    (so two different non-Latin app names never collide on 'app'); Windows reserved names get a suffix."""
    import unicodedata

    raw = name.strip()
    folded = unicodedata.normalize("NFKD", raw).encode("ascii", "ignore").decode("ascii")
    s = re.sub(r"[^a-zA-Z0-9]+", "-", folded.lower()).strip("-")
    if not s:
        s = ("app-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:8]) if raw.strip("/\\ .-_") else "app"
    if len(s) > SLUG_MAX:
        s = s[:SLUG_MAX].rstrip("-")
    if s in _WIN_RESERVED:
        s += "-app"
    return s


def is_safe_name(name: str) -> bool:
    """A single path component with no separators / traversal (used for --app / --run / LATEST values)."""
    return bool(name) and name not in (".", "..") and not re.search(r'[\\/:*?"<>|\x00]', name) and name == name.strip()


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while block := f.read(chunk):
            h.update(block)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def human_bytes(n: float) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def human_duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    return f"{h:d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


def truncate(text: str, n: int) -> str:
    return text if len(text) <= n else text[: max(0, n - 3)] + "..."


def jdump(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def jload(text, default=None):
    if text is None or text == "":
        return default
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return default


def normalize_host(host: str) -> str:
    """Lower-case, strip the trailing dot and brackets; internationalised names become punycode (IDNA)."""
    h = (host or "").strip().lower().rstrip(".")
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if h and not h.isascii():
        try:
            h = h.encode("idna").decode("ascii")
        except UnicodeError:
            pass
    return h


def clean_domain_entry(value) -> str:
    """Normalise a domain typed by a human in a manifest: 'https://Jan.AI/path' -> 'jan.ai'; '*.x.com' -> 'x.com'.

    Returns '' for anything that is not a plausible domain (caller decides whether that is an error).
    """
    if not isinstance(value, str):
        return ""
    v = value.strip().lower()
    v = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", v)  # scheme
    v = v.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    v = v.rsplit("@", 1)[-1]  # user:pass@
    if v.count(":") == 1 and not v.startswith("["):
        v = v.split(":", 1)[0]  # port
    v = v.lstrip("*").lstrip(".")  # wildcard prefix: '*.x.com' / '.x.com'
    v = normalize_host(v)
    if not v or not re.fullmatch(r"[a-z0-9]([a-z0-9\-_]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-_]*[a-z0-9])?)*", v):
        return ""
    return v


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def registrable_domain(host: str) -> str:
    """Approximate eTLD+1 (see _MULTI_SUFFIXES). IPs and single labels are returned unchanged.

    Hosts under a shared cloud/hosting parent (_HOST_EXACT) return the host itself: their neighbours are strangers.
    """
    host = normalize_host(host)
    if not host or is_ip(host) or "." not in host:
        return host
    labels = host.split(".")
    for n in range(len(labels) - 1, 0, -1):  # longest shared parent first
        if ".".join(labels[n:]) in _HOST_EXACT:
            return host
    if len(labels) >= 3 and ".".join(labels[-2:]) in _COUNTRY_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_shared_suffix(domain: str) -> bool:
    """True if `domain` is itself a shared cloud/hosting parent (never a legitimate 'first party' by itself)."""
    return normalize_host(domain) in _HOST_EXACT


def host_suffixes(host: str):
    """Yield host and every parent domain with at least two labels: a.b.c.com -> a.b.c.com, b.c.com, c.com."""
    host = normalize_host(host)
    labels = host.split(".")
    for i in range(len(labels)):
        cand = ".".join(labels[i:])
        if cand.count(".") >= 1:
            yield cand


def domain_matches(host: str, domain: str) -> bool:
    host, domain = normalize_host(host), normalize_host(domain)
    return bool(domain) and (host == domain or host.endswith("." + domain))


_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_UUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
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


def redact_text(text: str) -> str:
    """Mask e-mails, UUIDs, tokens/keys/JWTs, credentials, user names in paths, IPs/MACs and long numbers.

    Input should already be length-limited. KEEP IN SYNC with dynamic/addon.py:redact (a test enforces equality).
    """
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


def unique_path(directory: Path, stem: str, suffix: str) -> Path:
    """Return a path that does not exist yet (stem.suffix, stem-2.suffix, ...). Never overwrites."""
    directory.mkdir(parents=True, exist_ok=True)
    cand = directory / f"{stem}{suffix}"
    n = 2
    while cand.exists():
        cand = directory / f"{stem}-{n}{suffix}"
        n += 1
    return cand


def atomic_write_text(path: Path, text: str) -> None:
    """Write via temp file + os.replace. Used only for pointer/metadata files, never for evidence."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-", suffix=".part")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())  # pointer/metadata must survive a power cut (LATEST, run.json)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def expand_path(value: str, base: Path | None = None) -> str:
    """Expand ~ and %ENV%/$ENV; resolve relative paths against `base` (the manifest folder)."""
    if not value:
        return ""
    p = Path(os.path.expandvars(os.path.expanduser(value)))
    if not p.is_absolute() and base is not None:
        p = base / p
    return str(p)
