"""Static inspection: find telemetry SDKs inside an installed app (binary side) or a source repo (repo side).

Evidence kinds (with confidence):
  sdk_package    0.90  package name found in node_modules path / dependency manifest
  sdk_dependency 0.90  (repo side) dependency declared in a manifest or lockfile
  sdk_filename   0.85  a shipped file name matches a vendor SDK (e.g. Sentry.Core.dll)
  sdk_string     0.60  a vendor domain / API string appears inside file content

Resource control (see docs/06-hardware-resources.md): streaming chunked reads (bounded RAM), per-file and
total byte budgets, optional process pool, skip lists for media / runtime files. Everything skipped is
counted in `coverage` and shown in the report, so absence of evidence is never silently overstated.
"""

from __future__ import annotations

import fnmatch
import os
import re
import time
import zipfile
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

from claimcheck.manifest import StaticCfg
from claimcheck.signatures import SignatureSet
from claimcheck.static import asar
from claimcheck.static.repo_deps import parse_repo_dependencies

MB = 1024 * 1024
BINARY_UTF16_EXT = {".exe", ".dll", ".node", ".sys", ".ocx"}
ZIP_EXT = {".zip", ".nupkg", ".jar", ".vsix", ".whl"}
REPO_TEXT_EXT = {
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py", ".rs", ".go", ".cs", ".java", ".kt", ".swift",
    ".c", ".cc", ".cpp", ".h", ".hpp", ".json", ".toml", ".yaml", ".yml", ".xml", ".cfg", ".ini", ".vue", ".svelte",
}
MAX_EVIDENCE_PER_SDK = 25
# Compressed containers whose payload cannot be searched byte-wise: reported as NOT INSPECTED instead of silently "clean".
OPAQUE_EXT = {".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".zst", ".msi", ".cab", ".deb", ".rpm", ".dmg", ".pkg",
              ".appimage", ".snap", ".iso", ".msix", ".appx"}
_INSTALLER_NAME = re.compile(r"(?:^|[-_. ])(?:setup|install(?:er)?)[-_. \d]*.*\.exe$", re.I)
MAX_OPAQUE_LISTED = 20
_NODE_PKG = re.compile(r"(?:^|/)node_modules/((?:@[^/]+/)[^/]+|[^/@][^/]*)")

CONF = {"sdk_package": 0.90, "sdk_dependency": 0.90, "sdk_filename": 0.85, "sdk_string": 0.60}


@dataclass
class ScanResult:
    evidence: list = field(default_factory=list)
    coverage: dict = field(default_factory=dict)


# ---------------------------------------------------------------- path based detection
def path_evidence(rel: str, sigs: SignatureSet, side: str) -> list[dict]:
    out = []
    base = rel.rsplit("/", 1)[-1]
    v = sigs.match_filename(base)
    if v:
        out.append(_ev(side, v.id, "sdk_filename", rel, {"file": base}))
    for m in _NODE_PKG.finditer(rel):
        pkg = m.group(1)
        v = sigs.match_package("npm", pkg)
        if v:
            out.append(_ev(side, v.id, "sdk_package", rel, {"ecosystem": "npm", "package": pkg}))
    return out


def _ev(side: str, sdk_id: str, kind: str, location: str, detail: dict) -> dict:
    return {"side": side, "sdk_id": sdk_id, "kind": kind, "confidence": CONF[kind], "location": location, "detail": detail}


# ---------------------------------------------------------------- content scanning
def scan_chunks(chunks: Iterable[bytes], matcher) -> dict[str, dict]:
    acc: dict[str, dict] = {}
    tail = b""
    keep = max(0, matcher.max_len - 1)
    for chunk in chunks:
        joined = tail + chunk
        res = matcher.scan_chunk(joined.lower(), skip_before=len(tail))
        for sid, rec in res.items():
            a = acc.setdefault(sid, {"count": 0, "patterns": set()})
            a["count"] += rec["count"]
            a["patterns"] |= rec["patterns"]
        tail = joined[-keep:] if keep else b""
    return acc


def _iter_file_chunks(path: Path, chunk: int, limit: int) -> Iterator[bytes]:
    with open(path, "rb") as f:
        read = 0
        while read < limit:
            b = f.read(min(chunk, limit - read))
            if not b:
                break
            read += len(b)
            yield b


def _iter_zip_entry(zf: zipfile.ZipFile, info: zipfile.ZipInfo, chunk: int, limit: int) -> Iterator[bytes]:
    with zf.open(info) as f:
        read = 0
        while read < limit:
            b = f.read(min(chunk, limit - read))
            if not b:
                break
            read += len(b)
            yield b


def _content_evidence(side: str, location: str, res: dict[str, dict]) -> list[dict]:
    return [
        _ev(side, sid, "sdk_string", location, {"count": rec["count"], "patterns": sorted(rec["patterns"])[:6]})
        for sid, rec in res.items()
    ]


# ---------------------------------------------------------------- worker (top-level => picklable)
_SIG_CACHE: dict[str, SignatureSet] = {}


def _sigs_from_payload(payload: str) -> SignatureSet:
    s = _SIG_CACHE.get(payload)
    if s is None:
        _SIG_CACHE.clear()
        s = SignatureSet.from_payload(payload)
        _SIG_CACHE[payload] = s
    return s


def scan_physical_file(args: tuple) -> dict:
    """Scan one physical file (regular / .asar / zip-like). Returns plain dicts (picklable)."""
    path_s, rel, side, opts = args
    path = Path(path_s)
    sigs = _sigs_from_payload(opts["sig_payload"])
    chunk = opts["chunk_bytes"]
    max_file = opts["max_file_bytes"]
    skip_globs = opts["skip_globs"]
    res = {"rel": rel, "bytes": 0, "entries": 0, "skipped_entries": 0, "evidence": [], "error": ""}
    ext = path.suffix.lower()
    try:
        if ext == ".asar":
            for e in asar.iter_entries(path):
                erel = f"{rel}!/{e.path}"
                res["evidence"].extend(path_evidence(erel, sigs, side))
                base = e.path.rsplit("/", 1)[-1]
                if (e.unpacked or e.size > max_file or res["bytes"] + e.size > opts["archive_budget"]
                        or any(fnmatch.fnmatchcase(base.lower(), g) for g in skip_globs)):
                    res["skipped_entries"] += 1
                    continue
                matcher = sigs.matcher(Path(base).suffix.lower() in BINARY_UTF16_EXT)
                found = scan_chunks(asar.read_entry(path, e, chunk), matcher)
                res["bytes"] += e.size
                res["entries"] += 1
                res["evidence"].extend(_content_evidence(side, erel, found))
        elif ext in ZIP_EXT and zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    erel = f"{rel}!/{info.filename}"
                    res["evidence"].extend(path_evidence(erel, sigs, side))
                    base = info.filename.rsplit("/", 1)[-1]
                    if (info.file_size > max_file or res["bytes"] + info.file_size > opts["archive_budget"]
                            or any(fnmatch.fnmatchcase(base.lower(), g) for g in skip_globs)):
                        res["skipped_entries"] += 1  # includes zip-bomb protection: decompressed bytes are budgeted too
                        continue
                    matcher = sigs.matcher(Path(base).suffix.lower() in BINARY_UTF16_EXT)
                    found = scan_chunks(_iter_zip_entry(zf, info, chunk, max_file), matcher)
                    res["bytes"] += info.file_size
                    res["entries"] += 1
                    res["evidence"].extend(_content_evidence(side, erel, found))
        else:
            matcher = sigs.matcher(ext in BINARY_UTF16_EXT)
            found = scan_chunks(_iter_file_chunks(path, chunk, max_file), matcher)
            res["bytes"] = min(path.stat().st_size, max_file)
            res["entries"] = 1
            res["evidence"].extend(_content_evidence(side, rel, found))
    except Exception as e:  # noqa: BLE001  # ONE malformed file (truncated zip, weird asar...) must not abort the whole scan
        res["error"] = f"{type(e).__name__}: {e}"[:300]
    return res


# ---------------------------------------------------------------- discovery + orchestration
def _discover(root: Path) -> list[tuple[Path, str, int]]:
    root = Path(root)
    if root.is_file():
        return [(root, root.name, root.stat().st_size)]
    files: list[tuple[Path, str, int]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d != ".git")
        for fn in sorted(filenames):
            p = Path(dirpath) / fn
            try:
                if p.is_symlink():
                    continue
                files.append((p, p.relative_to(root).as_posix(), p.stat().st_size))
            except OSError:
                continue
    return files


def _merge_and_cap(evidence: list[dict]) -> tuple[list[dict], int]:
    seen = set()
    uniq = []
    for e in evidence:
        key = (e["side"], e["sdk_id"], e["kind"], e["location"])
        if key not in seen:
            seen.add(key)
            uniq.append(e)
    uniq.sort(key=lambda e: (-e["confidence"], e["sdk_id"], e["location"]))
    per: dict[str, int] = {}
    out, dropped = [], 0
    for e in uniq:
        k = (e["sdk_id"], e["kind"])
        per[k] = per.get(k, 0) + 1
        if per[k] > MAX_EVIDENCE_PER_SDK:
            dropped += 1
            continue
        out.append(e)
    return out, dropped


def _scan_tree(
    root: Path, side: str, sigs: SignatureSet, cfg: StaticCfg, text_only: bool,
    progress: Callable[[int, int, str], None] | None, log: Callable[[str], None] | None,
) -> ScanResult:
    t0 = time.time()
    log = log or (lambda m: None)
    chunk_bytes = max(1, cfg.chunk_mb) * MB
    max_file = cfg.max_file_mb * MB
    budget = cfg.max_total_mb * MB
    runtime = {n.lower() for n in cfg.runtime_files} if cfg.skip_runtime_files else set()
    skip_globs = [g.lower() for g in cfg.skip_globs]

    files = _discover(root)
    cov = {
        "root": str(root), "side": side, "files_seen": len(files), "files_scanned": 0, "bytes_scanned": 0,
        "skipped_glob": 0, "skipped_runtime": 0, "skipped_size": 0, "skipped_budget": 0, "skipped_ext": 0,
        "archive_entries_scanned": 0, "archive_entries_skipped": 0, "errors": [], "workers": cfg.workers,
        "opaque_containers": [], "opaque_container_count": 0,
        "max_file_mb": cfg.max_file_mb, "max_total_mb": cfg.max_total_mb, "evidence_dropped": 0, "seconds": 0.0,
    }
    evidence: list[dict] = []
    todo: list[tuple[Path, str, int]] = []
    used = 0
    for p, rel, size in files:
        evidence.extend(path_evidence(rel, sigs, side))  # cheap, independent of content budget
        base = p.name.lower()
        opaque = p.suffix.lower() in OPAQUE_EXT or (not text_only and size > 5 * MB and _INSTALLER_NAME.search(base))
        if opaque and not text_only:
            cov["opaque_container_count"] += 1
            if len(cov["opaque_containers"]) < MAX_OPAQUE_LISTED:
                cov["opaque_containers"].append(rel)
            log(f"not inspectable (compressed container / installer): {rel}")
            continue
        if text_only and p.suffix.lower() not in REPO_TEXT_EXT:
            cov["skipped_ext"] += 1
            continue
        if any(fnmatch.fnmatchcase(base, g) for g in skip_globs):
            cov["skipped_glob"] += 1
            continue
        if base in runtime:
            cov["skipped_runtime"] += 1
            log(f"skip runtime file: {rel}")
            continue
        if size > max_file:
            cov["skipped_size"] += 1
            log(f"skip too large ({size / MB:.0f} MB > {cfg.max_file_mb} MB): {rel}")
            continue
        if used + size > budget:
            cov["skipped_budget"] += 1
            continue
        used += size
        todo.append((p, rel, size))

    opts = {
        "sig_payload": sigs.to_payload(), "chunk_bytes": chunk_bytes, "max_file_bytes": max_file, "skip_globs": skip_globs,
        "archive_budget": budget,
    }
    jobs = [(str(p), rel, side, opts) for p, rel, _ in todo]
    total = len(jobs)
    done = 0

    def absorb(r: dict) -> None:
        nonlocal done
        done += 1
        evidence.extend(r["evidence"])
        cov["files_scanned"] += 1
        cov["bytes_scanned"] += r["bytes"]
        cov["archive_entries_scanned"] += max(0, r["entries"] - 1) if r["entries"] > 1 else 0
        cov["archive_entries_skipped"] += r["skipped_entries"]
        if r["error"]:
            cov["errors"].append(f"{r['rel']}: {r['error']}")
            log(f"scan error {r['rel']}: {r['error']}")
        if progress:
            progress(done, total, r["rel"])

    if cfg.workers > 1 and total > 1:
        try:
            with ProcessPoolExecutor(max_workers=cfg.workers) as ex:
                futs = [ex.submit(scan_physical_file, j) for j in jobs]
                for fut in as_completed(futs):
                    absorb(fut.result())
        except (OSError, RuntimeError) as e:  # pool could not start: fall back safely
            log(f"process pool failed ({e}); falling back to a single worker")
            cov["workers"] = 1
            done = 0
            evidence = [e2 for e2 in evidence if e2["kind"] != "sdk_string"]
            cov["files_scanned"] = cov["bytes_scanned"] = 0
            for j in jobs:
                absorb(scan_physical_file(j))
    else:
        cov["workers"] = 1
        for j in jobs:
            absorb(scan_physical_file(j))

    evidence, dropped = _merge_and_cap(evidence)
    cov["evidence_dropped"] = dropped
    cov["seconds"] = round(time.time() - t0, 2)
    return ScanResult(evidence, cov)


def scan_install(target: Path, sigs: SignatureSet, cfg: StaticCfg, progress=None, log=None) -> ScanResult:
    """Scan the installed app (directory, single binary, .asar or archive)."""
    return _scan_tree(Path(target), "binary", sigs, cfg, text_only=False, progress=progress, log=log)


def scan_repo(repo: Path, sigs: SignatureSet, cfg: StaticCfg, progress=None, log=None) -> ScanResult:
    """Scan the source repo: dependency manifests/lockfiles + source-string matches."""
    repo = Path(repo)
    log = log or (lambda m: None)
    deps, dstats = parse_repo_dependencies(repo)
    ev: list[dict] = []
    for d in deps:
        v = sigs.match_package(d.ecosystem, d.name)
        if v:
            ev.append(_ev("repo", v.id, "sdk_dependency", d.source_file, {"ecosystem": d.ecosystem, "package": d.name}))
    log(f"repo manifests parsed: {dstats['manifests_parsed']} ({len(deps)} dependencies, {len(ev)} telemetry matches)")
    res = _scan_tree(repo, "repo", sigs, cfg, text_only=True, progress=progress, log=log)
    merged, dropped = _merge_and_cap(ev + res.evidence)
    res.evidence = merged
    res.coverage.update({"dependencies_parsed": len(deps), **{f"deps_{k}": v for k, v in dstats.items()},
                         "evidence_dropped": res.coverage["evidence_dropped"] + dropped})
    return res
