"""App manifest: a YAML file describing ONE app under test. Validated with readable error messages.

A copy of the manifest is frozen inside every run folder (reproducibility). Unknown keys produce
warnings (typo detection); wrong types / missing required keys produce errors listing every problem.
"""

from __future__ import annotations

import copy
import json
import math
import re
from dataclasses import MISSING, asdict, dataclass, field, fields
from pathlib import Path

import yaml

from claimcheck.errors import ManifestError
from claimcheck.util import clean_domain_entry, expand_path, is_shared_suffix, slugify

DEFAULT_SKIP_GLOBS = [
    "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.svg", "*.webp", "*.bmp",
    "*.woff", "*.woff2", "*.ttf", "*.otf", "*.eot",
    "*.mp3", "*.mp4", "*.wav", "*.ogg", "*.webm",
    "*.pak", "*.dat", "*.lnk", "*.pdb", "*.map", "*.mo", "*.qm",
    "snapshot_blob.bin", "v8_context_snapshot.bin",
]
# Runtime files shipped by Chromium/Electron/Qt/CEF: not the app's own code, very large and noisy.
DEFAULT_RUNTIME_FILES = [
    "electron.exe", "chrome.dll", "chrome_elf.dll", "libcef.dll", "ffmpeg.dll", "libegl.dll",
    "libglesv2.dll", "d3dcompiler_47.dll", "vulkan-1.dll", "vk_swiftshader.dll", "dxcompiler.dll",
    "dxil.dll", "msedgewebview2.exe", "qt6core.dll", "qt6gui.dll", "qt6widgets.dll", "qt5core.dll",
    "qt5gui.dll", "qt5widgets.dll", "libcrypto-3-x64.dll", "libssl-3-x64.dll", "vcruntime140.dll",
    "msvcp140.dll", "ucrtbase.dll",
]


@dataclass
class AppInfo:
    name: str = ""
    slug: str = ""
    version: str = ""
    homepage: str = ""
    stack: str = ""  # free text: electron | tauri | qt | dotnet | native | ...
    exe_name: str = ""  # process image name, e.g. MyNotes.exe (used by local capture)
    exe_path: str = ""  # optional full path, only used if capture.launch_app = true
    install_dir: str = ""  # installed folder / unpacked archive / .asar / single binary
    installer_sha256: str = ""


@dataclass
class Document:
    type: str = "url"  # url | file
    location: str = ""
    role: str = "other"  # readme | homepage | privacy_policy | other


@dataclass
class Sources:
    repo_path: str = ""  # local clone (preferred: check out the SAME tag as the installed release)
    repo_url: str = ""  # optional: the tool can `git clone --depth 1` it into the run folder
    repo_ref: str = ""  # tag / branch for the clone
    documents: list = field(default_factory=list)


@dataclass
class CaptureCfg:
    mode: str = "local"  # local (Windows/macOS/Linux per-process) | regular (HTTP proxy on listen_port)
    listen_port: int = 8080
    idle_minutes: float = 5.0
    use_minutes: float = 0.0  # 0 = until you press Ctrl+C
    optout_minutes: float = 5.0
    launch_app: bool = False
    kill_app_at_end: bool = True
    mitmdump: str = "mitmdump"  # command; may contain args (e.g. "python -m mitmproxy.tools.dump")
    min_free_disk_mb: int = 2048
    min_free_ram_mb: int = 512
    max_flows: int = 200000
    store_payload_sample: bool = True
    payload_sample_bytes: int = 512
    heartbeat_seconds: float = 5.0
    canary_suffix: str = ""  # if set, hosts ending with it get a local 200 (used with the canary app)
    extra_args: list = field(default_factory=list)


@dataclass
class StaticCfg:
    max_file_mb: int = 300
    max_total_mb: int = 4096
    workers: int = 1
    chunk_mb: int = 8
    skip_runtime_files: bool = True
    skip_globs: list = field(default_factory=lambda: list(DEFAULT_SKIP_GLOBS))
    runtime_files: list = field(default_factory=lambda: list(DEFAULT_RUNTIME_FILES))
    extra_signatures: list = field(default_factory=list)


@dataclass
class ClassifyCfg:
    blocklists: list = field(default_factory=list)
    resolve_cname: bool = True
    telemetry_threshold: float = 0.7
    suspect_threshold: float = 0.4
    max_dns_lookups: int = 200
    dns_timeout: float = 3.0


@dataclass
class Manifest:
    schema_version: int = 1
    app: AppInfo = field(default_factory=AppInfo)
    first_party_domains: list = field(default_factory=list)
    allowed_domains: list = field(default_factory=list)
    sources: Sources = field(default_factory=Sources)
    capture: CaptureCfg = field(default_factory=CaptureCfg)
    static: StaticCfg = field(default_factory=StaticCfg)
    classify: ClassifyCfg = field(default_factory=ClassifyCfg)
    warnings: list = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("warnings", None)
        return d

    def documents_by_role(self, role: str) -> list[Document]:
        return [d for d in self.sources.documents if d.role == role]


_PATH_FIELDS = {
    "AppInfo": {"exe_path", "install_dir"},
    "Sources": {"repo_path"},
}
_VALID_MODES = {"local", "regular"}
_VALID_DOC_TYPES = {"url", "file"}
_VALID_ROLES = {"readme", "homepage", "privacy_policy", "other"}


def _default_of(f):
    if f.default is not MISSING:
        return f.default
    if f.default_factory is not MISSING:  # type: ignore[misc]
        return f.default_factory()  # type: ignore[misc]
    return None


def _coerce(value, default, where: str, problems: list):
    """Coerce YAML value to the type of `default`; on failure record a problem and use the default."""
    if isinstance(default, bool):
        if isinstance(value, bool):
            return value
        problems.append(f"{where}: expected true/false, got {value!r}")
        return default
    if isinstance(default, int):
        if isinstance(value, int) and not isinstance(value, bool):
            return value
        problems.append(f"{where}: expected an integer, got {value!r}")
        return default
    if isinstance(default, float):
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if not math.isfinite(float(value)):  # .inf / .nan would mean "capture forever" or break every comparison
                problems.append(f"{where}: must be a finite number, got {value!r}")
                return default
            return float(value)
        problems.append(f"{where}: expected a number, got {value!r}")
        return default
    if isinstance(default, str):
        if value is None:
            return ""
        if isinstance(value, (str, int, float)) and not isinstance(value, bool):
            return str(value)
        problems.append(f"{where}: expected text, got {value!r}")
        return default
    if isinstance(default, list):
        if value is None:
            return []
        if isinstance(value, list):
            return value
        problems.append(f"{where}: expected a list, got {value!r}")
        return default
    return value


def _build(cls, data, where: str, problems: list, warnings: list, base: Path | None):
    if data is None:
        data = {}
    if not isinstance(data, dict):
        problems.append(f"{where}: expected a mapping, got {type(data).__name__}")
        data = {}
    known = {f.name: f for f in fields(cls)}
    for key in data:
        if key not in known:
            warnings.append(f"{where}.{key}: unknown key ignored (typo?)")
    kwargs = {}
    path_fields = _PATH_FIELDS.get(cls.__name__, set())
    for name, f in known.items():
        if name in ("documents", "warnings"):
            continue
        default = _default_of(f)
        if name in data:
            val = _coerce(data[name], default, f"{where}.{name}", problems)
        else:
            val = default
        if name in path_fields and isinstance(val, str):
            val = expand_path(val, base)
        kwargs[name] = val
    return cls(**kwargs)


def _domains(value, where: str, problems: list, warnings: list) -> list[str]:
    """Human-typed domain list -> clean, de-duplicated hostnames. 'https://Jan.AI/x' and '*.jan.ai' are accepted and
    normalised (a URL left as-is would silently never match, mislabelling ALL first-party traffic as third party)."""
    raw = _coerce(value, [], where, problems)
    out: list[str] = []
    for i, item in enumerate(raw):
        clean = clean_domain_entry(item)
        if not clean:
            problems.append(f"{where}[{i}]: {item!r} is not a valid domain name")
            continue
        if isinstance(item, str) and item.strip().lower() != clean:
            warnings.append(f"{where}[{i}]: {item!r} normalised to {clean!r}")
        if is_shared_suffix(clean):
            warnings.append(f"{where}[{i}]: {clean!r} is a shared cloud/hosting domain: it will be matched exactly, "
                            "use the full hostname of YOUR service (e.g. myapp.s3.amazonaws.com)")
        if clean not in out:
            out.append(clean)
    return out


def _repo_url_ok(url: str) -> bool:
    """No whitespace, allowed scheme, and a host that cannot be parsed by git as an option (e.g. ssh://-oProxyCommand=...)."""
    if not re.match(r"^(https://|http://|ssh://|git@)[^\s]+$", url):
        return False
    rest = re.sub(r"^(https?://|ssh://|git@)", "", url)
    host = rest.rsplit("@", 1)[-1] if "@" in rest.split("/", 1)[0] else rest
    return not host.startswith("-") and "\x00" not in url


def parse_manifest(data: dict, base: Path | None = None) -> Manifest:
    problems: list[str] = []
    warnings: list[str] = []
    if not isinstance(data, dict):
        raise ManifestError("Manifest root must be a YAML mapping.")
    known_top = {f.name for f in fields(Manifest)} - {"warnings"}
    for key in data:
        if key not in known_top:
            warnings.append(f"{key}: unknown top-level key ignored (typo?)")

    m = Manifest()
    m.schema_version = _coerce(data.get("schema_version", 1), 1, "schema_version", problems)
    if m.schema_version != 1:
        problems.append(f"schema_version: unsupported version {m.schema_version} (this tool supports 1)")
    m.app = _build(AppInfo, data.get("app"), "app", problems, warnings, base)
    m.sources = _build(Sources, data.get("sources"), "sources", problems, warnings, base)
    m.capture = _build(CaptureCfg, data.get("capture"), "capture", problems, warnings, base)
    m.static = _build(StaticCfg, data.get("static"), "static", problems, warnings, base)
    m.classify = _build(ClassifyCfg, data.get("classify"), "classify", problems, warnings, base)
    m.first_party_domains = _domains(data.get("first_party_domains"), "first_party_domains", problems, warnings)
    m.allowed_domains = _domains(data.get("allowed_domains"), "allowed_domains", problems, warnings)
    m.static.extra_signatures = [expand_path(str(x), base) for x in m.static.extra_signatures]
    m.classify.blocklists = [expand_path(str(x), base) for x in m.classify.blocklists]

    docs_raw = (data.get("sources") or {}).get("documents") if isinstance(data.get("sources"), dict) else None
    for i, d in enumerate(docs_raw or []):
        where = f"sources.documents[{i}]"
        doc = _build(Document, d, where, problems, warnings, base)
        if doc.type not in _VALID_DOC_TYPES:
            problems.append(f"{where}.type: must be one of {sorted(_VALID_DOC_TYPES)}, got {doc.type!r}")
        if doc.role not in _VALID_ROLES:
            problems.append(f"{where}.role: must be one of {sorted(_VALID_ROLES)}, got {doc.role!r}")
        if not doc.location:
            problems.append(f"{where}.location: required")
        elif doc.type == "url" and not re.match(r"^https?://[^\s]+$", doc.location):
            problems.append(f"{where}.location: a 'url' document must start with http:// or https:// (got {doc.location!r})")
        elif doc.type == "file":
            doc.location = expand_path(doc.location, base)
        m.sources.documents.append(doc)

    # ---- cross-field validation ----
    if not m.app.name:
        problems.append("app.name: required")
    if not m.app.slug:
        m.app.slug = slugify(m.app.name)
    else:
        m.app.slug = slugify(m.app.slug)
    if m.capture.mode not in _VALID_MODES:
        problems.append(f"capture.mode: must be one of {sorted(_VALID_MODES)}, got {m.capture.mode!r}")
    if m.capture.mode == "local" and not m.app.exe_name:
        warnings.append("app.exe_name is empty: capture.mode=local needs the process image name (e.g. MyApp.exe)")
    if not (1 <= m.capture.listen_port <= 65535):
        problems.append("capture.listen_port: must be 1-65535")
    for k in ("idle_minutes", "use_minutes", "optout_minutes"):
        if getattr(m.capture, k) < 0:
            problems.append(f"capture.{k}: must be >= 0")
    c = m.capture
    if c.heartbeat_seconds <= 0:
        problems.append("capture.heartbeat_seconds: must be > 0")
    for k in ("min_free_disk_mb", "min_free_ram_mb", "max_flows"):
        if getattr(c, k) < 0:
            problems.append(f"capture.{k}: must be >= 0")
    if not (0 <= c.payload_sample_bytes <= 65536):
        problems.append("capture.payload_sample_bytes: must be between 0 and 65536")
    if m.static.workers < 1 or m.static.workers > 64:
        problems.append("static.workers: must be between 1 and 64")
    if m.static.chunk_mb < 1 or m.static.chunk_mb > 1024:
        problems.append("static.chunk_mb: must be between 1 and 1024")
    if m.static.max_file_mb < 1:
        problems.append("static.max_file_mb: must be >= 1")
    if m.static.max_total_mb < 1:
        problems.append("static.max_total_mb: must be >= 1")
    if m.classify.max_dns_lookups < 0:
        problems.append("classify.max_dns_lookups: must be >= 0")
    if not (0 < m.classify.dns_timeout <= 60):
        problems.append("classify.dns_timeout: must be > 0 and <= 60 seconds")
    for k in ("skip_globs", "runtime_files", "extra_signatures"):
        if any(not isinstance(x, str) for x in getattr(m.static, k)):
            problems.append(f"static.{k}: every item must be text")
    if any(not isinstance(x, (str, int, float)) for x in c.extra_args):
        problems.append("capture.extra_args: every item must be text")
    if re.search(r"webview|tauri|wry|maui", m.app.stack, re.I) and m.app.exe_name and "webview2" not in m.app.exe_name.lower() and c.mode == "local":
        warnings.append("app.stack looks WebView2-based: its web content runs in msedgewebview2.exe, which capture.mode=local "
                        "does NOT see unless it is listed. Use a comma-separated app.exe_name, e.g. \"MyApp.exe,msedgewebview2.exe\".")
    if not (0 < m.classify.suspect_threshold < m.classify.telemetry_threshold <= 1):
        problems.append("classify: need 0 < suspect_threshold < telemetry_threshold <= 1")
    if m.sources.repo_url and not _repo_url_ok(m.sources.repo_url):
        problems.append("sources.repo_url: must start with https://, http://, ssh:// or git@, contain no spaces and a host not starting with '-'")
    ref = m.sources.repo_ref
    if ref and (ref.startswith("-") or not re.fullmatch(r"[A-Za-z0-9._/\-]+", ref)):
        problems.append("sources.repo_ref: only letters, digits and ._/- are allowed, and it cannot start with '-'")
    if not m.sources.documents and not m.sources.repo_path:
        warnings.append("no sources.documents and no sources.repo_path: the 'claims' phase will find nothing")

    if problems:
        raise ManifestError(
            "Invalid manifest:\n  - " + "\n  - ".join(problems),
            hint="Fix the listed keys (see docs/03-input-data-collection.md) and retry.",
        )
    m.warnings = warnings
    return m


MAX_MANIFEST_BYTES = 1024 * 1024


def read_text_smart(path: Path) -> str:
    """Read a text file that a human (or PowerShell's `>` redirection, which writes UTF-16 LE) may have produced."""
    return decode_text_smart(Path(path).read_bytes())


def decode_text_smart(raw: bytes) -> str:
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8")
    return raw.decode("utf-8")


def parse_manifest_bytes(raw: bytes, base: Path) -> Manifest:
    """Parse manifest bytes already read ONCE (so the validated text and the frozen copy can never differ)."""
    try:
        data = yaml.safe_load(decode_text_smart(raw))
    except UnicodeDecodeError as e:
        raise ManifestError(f"Manifest is not valid UTF-8/UTF-16 text ({e.reason})", hint="Re-save it as UTF-8.") from e
    except yaml.YAMLError as e:
        raise ManifestError(f"Manifest is not valid YAML: {e}") from e
    return parse_manifest(data or {}, base=Path(base))


def load_manifest(path: Path, base: Path | None = None) -> Manifest:
    """`base`: folder used to resolve relative paths (defaults to the manifest's own folder)."""
    path = Path(path)
    if not path.is_file():
        raise ManifestError(f"Manifest not found: {path}", hint="Create one with: claimcheck new <name>")
    try:
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            raise ManifestError(f"Manifest is suspiciously large ({path.stat().st_size} bytes): {path}")
        text = read_text_smart(path)
    except UnicodeDecodeError as e:
        raise ManifestError(f"Manifest is not valid UTF-8/UTF-16 text: {path} ({e.reason})",
                            hint="Re-save it as UTF-8 (in VS Code: bottom-right encoding > Save with Encoding > UTF-8).") from e
    except OSError as e:
        raise ManifestError(f"Cannot read manifest {path}: {e}") from e
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise ManifestError(f"Manifest is not valid YAML: {e}") from e
    return parse_manifest(data or {}, base=Path(base) if base else path.parent)


def clone_manifest_dict(m: Manifest) -> dict:
    return copy.deepcopy(m.to_dict())


TEMPLATE = """\
# ClaimCheck app manifest - one file per app under test. See docs/03-input-data-collection.md
schema_version: 1

app:
  name: {name}
  slug: {slug}                # used for the runs/<slug>/ folder
  version: ""                   # the exact release you install (e.g. 1.4.2)
  homepage: {homepage}
  stack: {stack}              # electron | tauri | qt | dotnet | native ...
  exe_name: {exe_name}        # process image name shown in Task Manager (needed for capture.mode=local)
  exe_path: ""                  # optional full path (only if capture.launch_app: true)
  install_dir: ""               # e.g. C:\\Users\\you\\AppData\\Local\\Programs\\MyApp  (inside the VM)
  installer_sha256: ""          # sha256 of the installer you downloaded (reproducibility)

# Domains the vendor legitimately owns (traffic to them is "first party").
first_party_domains: [{first_party}]
# Domains you consider expected/benign for this app (update servers, model downloads...).
allowed_domains: []

sources:
  repo_path: ""                 # local git clone checked out at the SAME tag as the installed release
  repo_url: {repo_url}        # alternative: the tool clones it (needs git)
  repo_ref: ""                  # tag/branch for the clone
  documents:
{documents}

capture:
  mode: local                   # local = mitmproxy per-process capture (needs Administrator on Windows)
  idle_minutes: 5
  use_minutes: 0                # 0 = until you press Ctrl+C
  optout_minutes: 5
  launch_app: false
  min_free_disk_mb: 2048
  min_free_ram_mb: 512

static:
  max_file_mb: 300
  max_total_mb: 4096
  workers: 1                    # raise only if `claimcheck doctor` says you have spare CPU/RAM

classify:
  resolve_cname: true
  blocklists: []                # e.g. lists downloaded with `claimcheck fetch-lists`
"""


def render_template(
    name: str,
    slug: str = "",
    homepage: str = "",
    stack: str = "",
    exe_name: str = "",
    first_party: list | None = None,
    repo_url: str = "",
    documents: list | None = None,
) -> str:
    docs = documents or [
        {"type": "url", "location": "https://example.org/privacy", "role": "privacy_policy"},
        {"type": "url", "location": "https://example.org", "role": "homepage"},
    ]
    q = json.dumps  # a JSON string is a valid YAML double-quoted scalar: quotes/backslashes/unicode can never break the file
    doc_lines = "\n".join(
        f"    - {{type: {q(d['type'])}, location: {q(d['location'])}, role: {q(d['role'])}}}" for d in docs
    )
    return TEMPLATE.format(
        name=q(name),
        slug=q(slug or slugify(name)),
        homepage=q(homepage),
        stack=q(stack),
        exe_name=q(exe_name),
        first_party=", ".join(q(d) for d in (first_party or [])),
        repo_url=q(repo_url),
        documents=doc_lines,
    )
