"""Load telemetry signatures (bundled + user extras) and expose fast matchers."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

import yaml

from claimcheck.errors import ClaimCheckError
from claimcheck.manifest import read_text_smart
from claimcheck.util import clean_domain_entry, host_suffixes, normalize_host

ECOSYSTEMS = ("npm", "pypi", "cargo", "go", "nuget")


@dataclass
class Vendor:
    id: str
    name: str
    category: str = "analytics"
    policy_names: list = field(default_factory=list)
    domains: list = field(default_factory=list)
    packages: dict = field(default_factory=dict)
    file_names: list = field(default_factory=list)
    strings: list = field(default_factory=list)


def _norm_pkg(eco: str, name: str) -> str:
    name = name.strip().lower()
    if eco == "pypi":
        name = re.sub(r"[-_.]+", "-", name)
    return name


_ALNUM = frozenset(b"abcdefghijklmnopqrstuvwxyz0123456789-_")


class ContentMatcher:
    """Byte-substring matcher (find-loop on lower-cased chunks). Simple, exact, no regex backtracking.

    Domain-like needles ('count.ly') must start at a word boundary: without it 'count.ly' matches inside
    'account.ly' or 'discount.ly' and reports a telemetry SDK that is not there.
    """

    def __init__(self, patterns: list[tuple[str, str]], utf16: bool):
        # patterns: (sdk_id, pattern_text) ; needles are lower-case bytes
        seen: dict[bytes, tuple[str, str]] = {}
        self._boundary: dict[bytes, int] = {}  # needle -> width in bytes of the char that must NOT precede it (0 = no check)
        for sdk_id, text in patterns:
            low = text.lower()
            domain_like = low[:1].isalnum() and "." in low and "/" not in low and "@" not in low
            for enc, width in (("utf-8", 1), ("utf-16-le", 2)) if utf16 else (("utf-8", 1),):
                nb = low.encode(enc)
                if nb not in seen:
                    seen[nb] = (sdk_id, text)
                    self._boundary[nb] = width if domain_like else 0
        self.needles = seen
        self.max_len = max((len(n) for n in seen), default=1)

    def _boundary_ok(self, data: bytes, i: int, width: int) -> bool:
        if width == 0 or i < width:
            return True
        if width == 1:
            return data[i - 1] not in _ALNUM
        return not (data[i - 1] == 0 and data[i - 2] in _ALNUM)

    def scan_chunk(self, data_lower: bytes, skip_before: int = 0, cap: int = 50) -> dict[str, dict]:
        """`skip_before`: ignore matches that end at or before this offset (already counted in previous chunk)."""
        out: dict[str, dict] = {}
        for needle, (sdk_id, text) in self.needles.items():
            start, n = 0, 0
            width = self._boundary.get(needle, 0)
            while n < cap:
                i = data_lower.find(needle, start)
                if i < 0:
                    break
                start = i + 1
                if i + len(needle) <= skip_before or not self._boundary_ok(data_lower, i, width):
                    continue
                n += 1
            if n:
                rec = out.setdefault(sdk_id, {"count": 0, "patterns": set()})
                rec["count"] += n
                rec["patterns"].add(text)
        return out


class SignatureSet:
    def __init__(self, vendors: dict[str, Vendor]):
        self.vendors = vendors
        self.overridden: list[str] = []
        self._domain_index: dict[str, str] = {}
        for v in vendors.values():
            for d in v.domains:
                self._domain_index[normalize_host(d)] = v.id
        self._pkg_patterns: dict[str, list[tuple[str, str]]] = {e: [] for e in ECOSYSTEMS}
        for v in vendors.values():
            for eco, pats in (v.packages or {}).items():
                if eco in self._pkg_patterns:
                    for p in pats:
                        self._pkg_patterns[eco].append((_norm_pkg(eco, p), v.id))
        self._file_patterns = [(p.lower(), v.id) for v in vendors.values() for p in v.file_names]
        self._matchers: dict[bool, ContentMatcher] = {}

    # ---- lookups --------------------------------------------------------
    def get(self, sdk_id: str) -> Vendor | None:
        return self.vendors.get(sdk_id)

    def match_domain(self, host: str) -> Vendor | None:
        for cand in host_suffixes(host):
            sid = self._domain_index.get(cand)
            if sid:
                return self.vendors[sid]
        return None

    def match_package(self, ecosystem: str, name: str) -> Vendor | None:
        name = _norm_pkg(ecosystem, name)
        for pat, sid in self._pkg_patterns.get(ecosystem, []):
            if fnmatch.fnmatchcase(name, pat):
                return self.vendors[sid]
        return None

    def match_filename(self, basename: str) -> Vendor | None:
        b = basename.lower()
        for pat, sid in self._file_patterns:
            if fnmatch.fnmatchcase(b, pat):
                return self.vendors[sid]
        return None

    def content_patterns(self) -> list[tuple[str, str]]:
        out = []
        for v in self.vendors.values():
            for s in v.strings:
                out.append((v.id, s))
            for d in v.domains:
                if "." in d and len(d) >= 8:  # very short domains would be too noisy as raw strings
                    out.append((v.id, d))
        return out

    def matcher(self, utf16: bool) -> ContentMatcher:
        if utf16 not in self._matchers:
            self._matchers[utf16] = ContentMatcher(self.content_patterns(), utf16)
        return self._matchers[utf16]

    def all_domains(self) -> list[str]:
        return sorted(self._domain_index)

    # ---- (de)serialisation for worker processes -------------------------
    def to_payload(self) -> str:
        return json.dumps([v.__dict__ for v in self.vendors.values()], sort_keys=True)

    @classmethod
    def from_payload(cls, payload: str) -> SignatureSet:
        return cls({d["id"]: Vendor(**d) for d in json.loads(payload)})

    def digest(self) -> str:
        return hashlib.sha256(self.to_payload().encode()).hexdigest()[:12]


_LIST_FIELDS = ("policy_names", "domains", "file_names", "strings")


def _str_list(v: dict, key: str, origin: str) -> list[str]:
    val = v.get(key)
    if val is None:
        return []
    if not isinstance(val, list) or any(not isinstance(x, str) or not x.strip() for x in val):
        # a bare string would be iterated CHARACTER BY CHARACTER downstream (every 'f' would become a signature)
        raise ClaimCheckError(f"{origin}: vendor '{v.get('id')}': '{key}' must be a list of non-empty strings, got {val!r}")
    return [x.strip() for x in val]


def _parse_vendor_file(data: dict, origin: str) -> dict[str, Vendor]:
    if not isinstance(data, dict) or not isinstance(data.get("vendors"), list):
        raise ClaimCheckError(f"Signature file {origin} must contain a 'vendors:' list")
    out: dict[str, Vendor] = {}
    for i, v in enumerate(data["vendors"]):
        if not isinstance(v, dict) or not isinstance(v.get("id"), str) or not re.fullmatch(r"[A-Za-z0-9_\-]+", v["id"]):
            raise ClaimCheckError(f"{origin}: vendors[{i}] needs an 'id' made of letters, digits, '_' or '-'")
        unknown = set(v) - set(Vendor.__dataclass_fields__)
        if unknown:
            raise ClaimCheckError(f"{origin}: vendor '{v['id']}' has unknown keys {sorted(unknown)}")
        fields_ = {k: _str_list(v, k, origin) for k in _LIST_FIELDS}
        doms = []
        for d in fields_["domains"]:
            clean = clean_domain_entry(d)
            if not clean or "." not in clean:
                raise ClaimCheckError(f"{origin}: vendor '{v['id']}': {d!r} is not a valid domain")
            doms.append(clean)
        fields_["domains"] = doms
        pk = v.get("packages") or {}
        if not isinstance(pk, dict):
            raise ClaimCheckError(f"{origin}: vendor '{v['id']}': 'packages' must be a mapping ecosystem -> list")
        for eco, pats in pk.items():
            if eco not in ECOSYSTEMS:
                raise ClaimCheckError(f"{origin}: vendor '{v['id']}': unknown ecosystem '{eco}' (use one of {', '.join(ECOSYSTEMS)})")
            if not isinstance(pats, list) or any(not isinstance(x, str) for x in pats):
                raise ClaimCheckError(f"{origin}: vendor '{v['id']}': packages.{eco} must be a list of strings")
        name = v.get("name", v["id"])
        cat = v.get("category", "analytics")
        if not isinstance(name, str) or not isinstance(cat, str):
            raise ClaimCheckError(f"{origin}: vendor '{v['id']}': 'name' and 'category' must be text")
        out[v["id"]] = Vendor(id=v["id"], name=name, category=cat, packages={k: list(x) for k, x in pk.items()}, **fields_)
    return out


def _load_yaml(text: str, origin: str):
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise ClaimCheckError(f"Signature file {origin} is not valid YAML: {e}") from e


def load_signatures(extra_files: list[str] | None = None) -> SignatureSet:
    text = resources.files("claimcheck").joinpath("data/telemetry_signatures.yaml").read_text(encoding="utf-8")
    vendors = _parse_vendor_file(_load_yaml(text, "bundled telemetry_signatures.yaml"), "bundled telemetry_signatures.yaml")
    overridden: list[str] = []
    for f in extra_files or []:
        p = Path(f)
        if not p.is_file():
            raise ClaimCheckError(f"Extra signature file not found: {p}")
        try:
            extra = _parse_vendor_file(_load_yaml(read_text_smart(p), str(p)), str(p))
        except UnicodeDecodeError as e:
            raise ClaimCheckError(f"Extra signature file {p} is not valid UTF-8 text") from e
        overridden += [k for k in extra if k in vendors]
        vendors.update(extra)
    sset = SignatureSet(vendors)
    sset.overridden = sorted(set(overridden))  # extra files replacing a bundled vendor: surfaced as a warning by the caller
    return sset
