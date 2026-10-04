"""Optional third-party blocklists (NOT bundled: licenses differ; the user downloads them).

Supported formats: hosts files, plain domain lists, AdGuard/ABP domain rules (||example.com^), and the
Disconnect `services.json`. Only domain-level information is used.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from pathlib import Path

import requests

from claimcheck.errors import ClaimCheckError
from claimcheck.util import host_suffixes, is_ip, normalize_host

DEFAULT_LISTS_DIR = Path.home() / ".claimcheck" / "lists"
DISCONNECT_URL = "https://raw.githubusercontent.com/disconnectme/disconnect-tracking-protection/master/services.json"
DISCONNECT_CATEGORIES = {"Advertising", "Analytics", "FingerprintingInvasive", "FingerprintingGeneral"}
_DOMAIN = re.compile(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$")


MAX_LIST_BYTES = 64 * 1024 * 1024


class Blocklist:
    def __init__(self) -> None:
        self.domains: dict[str, str] = {}  # domain -> "source:category"
        self.sources: list[str] = []
        self.provenance: list[dict] = []  # [{name, sha256, domains}] -> recorded in the classify attempt (reproducibility)

    def add_file(self, path: Path) -> int:
        path = Path(path)
        if path.stat().st_size > MAX_LIST_BYTES:
            raise ValueError(f"blocklist larger than {MAX_LIST_BYTES // (1024 * 1024)} MB")
        raw = path.read_bytes()
        text = raw.decode("utf-8", errors="replace")
        before = len(self.domains)
        src = path.name
        if text.lstrip().startswith("{"):
            self._add_disconnect(json.loads(text), src)
        else:
            for line in text.splitlines():
                line = line.split("#", 1)[0].strip()
                if not line or line.startswith(("!", "[")):
                    continue
                if line.startswith("||"):
                    cands = [line[2:].split("^", 1)[0].split("/", 1)[0]]
                else:
                    parts = line.split()
                    # hosts format: "0.0.0.0 a.com b.com" -> every name after the address; plain list: the token itself
                    cands = parts[1:] if len(parts) > 1 and is_ip(parts[0]) else parts[:1]
                for dom in cands:
                    dom = normalize_host(dom)
                    if _DOMAIN.match(dom) and not is_ip(dom):
                        self.domains.setdefault(dom, src)
        added = len(self.domains) - before
        self.sources.append(src)
        self.provenance.append({"name": src, "sha256": hashlib.sha256(raw).hexdigest(), "domains": added})
        return added

    def _add_disconnect(self, data: dict, src: str) -> None:
        """Disconnect services.json: categories -> [ {Company: {url: [domains...], "dnt": "eff", ...}} ]. Only real
        domain lists are taken (a string value such as "dnt": "eff" would otherwise be iterated character by character)."""
        cats = data.get("categories") if isinstance(data, dict) else None
        if not isinstance(cats, dict):
            raise ValueError("not a Disconnect services.json (missing 'categories')")
        for cat, companies in cats.items():
            if cat not in DISCONNECT_CATEGORIES or not isinstance(companies, list):
                continue
            for company in companies:
                if not isinstance(company, dict):
                    continue
                for urls in company.values():
                    if not isinstance(urls, dict):
                        continue
                    for doms in urls.values():
                        if not isinstance(doms, list):
                            continue
                        for d in doms:
                            d = normalize_host(d) if isinstance(d, str) else ""
                            if _DOMAIN.match(d) and not is_ip(d):
                                self.domains.setdefault(d, f"{src}:{cat}")

    def match(self, host: str) -> str | None:
        for cand in host_suffixes(host):
            hit = self.domains.get(cand)
            if hit:
                return f"{cand} ({hit})"
        return None

    def __len__(self) -> int:
        return len(self.domains)


def load_blocklists(paths: list[str], include_default_dir: bool = True, log: Callable[[str], None] | None = None) -> Blocklist:
    log = log or (lambda m: None)
    bl = Blocklist()
    files = [Path(p) for p in paths]
    if include_default_dir and DEFAULT_LISTS_DIR.is_dir():
        files += sorted(p for p in DEFAULT_LISTS_DIR.glob("*") if p.suffix.lower() not in (".part", ".tmp"))
    for f in files:
        if not f.is_file():
            log(f"blocklist not found (skipped): {f}")
            continue
        try:
            n = bl.add_file(f)
            log(f"blocklist {f.name}: +{n} domains")
        except (OSError, ValueError, AttributeError, TypeError) as e:
            log(f"blocklist {f.name} unreadable ({e}); skipped")
    return bl


def fetch_default_lists(dest: Path = DEFAULT_LISTS_DIR, timeout: float = 60.0) -> list[Path]:
    """Download the Disconnect list into `dest` (never overwrites: timestamped copy)."""
    from claimcheck.util import unique_path

    dest.mkdir(parents=True, exist_ok=True)
    try:
        r = requests.get(DISCONNECT_URL, timeout=timeout, headers={"User-Agent": "claimcheck/0.2"})
        r.raise_for_status()
        json.loads(r.text)  # validate
    except (requests.RequestException, ValueError) as e:
        raise ClaimCheckError(f"Could not download Disconnect list: {e}", hint="Check your connection or download it manually into " + str(dest)) from e
    out = unique_path(dest, "disconnect-services", ".json")
    tmp = out.with_name(out.name + ".part")
    tmp.write_text(r.text, encoding="utf-8")
    tmp.replace(out)  # a crash mid-download leaves a *.part file (ignored below), never a truncated list
    return [out]
