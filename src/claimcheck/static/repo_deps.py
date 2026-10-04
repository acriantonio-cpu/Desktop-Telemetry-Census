"""Extract dependency names from a source repository (manifests + lockfiles).

Why: to answer "does the shipped binary contain a telemetry SDK that the *source repo* never declares?"
Lockfiles are included so transitive dependencies are not mistaken for undeclared ones.
Supported: package.json, package-lock.json, yarn.lock, requirements*.txt, pyproject.toml, poetry.lock,
uv.lock, Cargo.toml, Cargo.lock, go.mod, *.csproj / packages.config / Directory.Packages.props.
Not supported (documented limitation): pnpm-lock.yaml, Gradle, CMake/vcpkg/conan.
"""

from __future__ import annotations

import json
import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_MANIFESTS = 600
PRUNE_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "target", "dist", "build", ".tox", "vendor", ".next"}


@dataclass(frozen=True)
class Dependency:
    ecosystem: str
    name: str
    source_file: str  # relative to the repo root


def _read(path: Path) -> str:
    if path.stat().st_size > MAX_MANIFEST_BYTES:
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _npm_from_package_json(text: str) -> set[str]:
    try:
        data = json.loads(text)
    except ValueError:
        return set()
    names: set[str] = set()
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        if isinstance(data.get(key), dict):
            names.update(data[key])
    return names


def _npm_from_package_lock(text: str) -> set[str]:
    try:
        data = json.loads(text)
    except ValueError:
        return set()
    names: set[str] = set()
    for key in (data.get("packages") or {}):
        if "node_modules/" in key:
            names.add(key.rsplit("node_modules/", 1)[1])

    def walk(deps: dict):
        for n, d in (deps or {}).items():
            names.add(n)
            if isinstance(d, dict):
                walk(d.get("dependencies") or {})

    if isinstance(data.get("dependencies"), dict):
        walk(data["dependencies"])
    return names


_YARN = re.compile(r'^"?(@?[^@\s",]+)@', re.M)


def _npm_from_yarn_lock(text: str) -> set[str]:
    return set(_YARN.findall(text))


_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)")


def _pypi_from_requirements(text: str) -> set[str]:
    names = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = _REQ.match(line)
        if m:
            names.add(m.group(1))
    return names


def _pypi_from_pyproject(text: str) -> set[str]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return set()
    names: set[str] = set()
    proj = data.get("project") or {}
    for spec in proj.get("dependencies") or []:
        m = _REQ.match(spec)
        if m:
            names.add(m.group(1))
    for group in (proj.get("optional-dependencies") or {}).values():
        for spec in group:
            m = _REQ.match(spec)
            if m:
                names.add(m.group(1))
    for group in (data.get("dependency-groups") or {}).values():
        for spec in group:
            if isinstance(spec, str):
                m = _REQ.match(spec)
                if m:
                    names.add(m.group(1))
    poetry = (data.get("tool") or {}).get("poetry") or {}
    for key in ("dependencies", "dev-dependencies"):
        names.update(k for k in (poetry.get(key) or {}) if k.lower() != "python")
    return names


_LOCK_NAME = re.compile(r'^name\s*=\s*"([^"]+)"', re.M)


def _names_from_toml_lock(text: str) -> set[str]:
    return set(_LOCK_NAME.findall(text))


def _cargo_from_toml(text: str) -> set[str]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return set()
    names: set[str] = set()

    def take(table):
        for k, v in (table or {}).items():
            names.add(v["package"] if isinstance(v, dict) and "package" in v else k)

    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        take(data.get(key))
    take((data.get("workspace") or {}).get("dependencies"))
    for tgt in (data.get("target") or {}).values():
        if isinstance(tgt, dict):
            for key in ("dependencies", "dev-dependencies", "build-dependencies"):
                take(tgt.get(key))
    return names


_GO_REQ = re.compile(r"^\s*(?:require\s+)?([A-Za-z0-9._\-]+\.[A-Za-z0-9._\-/]+)\s+v[0-9]", re.M)


def _go_from_mod(text: str) -> set[str]:
    return set(_GO_REQ.findall(text))


_NUGET = re.compile(r'<(?:PackageReference|PackageVersion)\s+[^>]*?Include="([^"]+)"|<package\s+id="([^"]+)"', re.I)


def _nuget(text: str) -> set[str]:
    return {a or b for a, b in _NUGET.findall(text)}


def _handler_for(name: str):
    n = name.lower()
    if n == "package.json":
        return "npm", _npm_from_package_json
    if n == "package-lock.json":
        return "npm", _npm_from_package_lock
    if n == "yarn.lock":
        return "npm", _npm_from_yarn_lock
    if re.fullmatch(r"requirements[\w.\-]*\.txt", n):
        return "pypi", _pypi_from_requirements
    if n == "pyproject.toml":
        return "pypi", _pypi_from_pyproject
    if n in ("poetry.lock", "uv.lock"):
        return "pypi", _names_from_toml_lock
    if n == "cargo.toml":
        return "cargo", _cargo_from_toml
    if n == "cargo.lock":
        return "cargo", _names_from_toml_lock
    if n == "go.mod":
        return "go", _go_from_mod
    if n.endswith(".csproj") or n in ("packages.config", "directory.packages.props"):
        return "nuget", _nuget
    return None


def parse_repo_dependencies(repo: Path) -> tuple[list[Dependency], dict]:
    """Return (dependencies, stats). Never raises on malformed manifests (they are counted in stats)."""
    repo = Path(repo)
    deps: dict[tuple[str, str], Dependency] = {}
    stats = {"manifests_parsed": 0, "manifests_skipped": 0, "truncated": False}
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = [d for d in dirnames if d not in PRUNE_DIRS]
        for fn in filenames:
            h = _handler_for(fn)
            if not h:
                continue
            if stats["manifests_parsed"] >= MAX_MANIFESTS:
                stats["truncated"] = True
                return list(deps.values()), stats
            eco, fn_parse = h
            p = Path(dirpath) / fn
            try:
                text = _read(p)
                names = fn_parse(text) if text else set()
            except (OSError, ValueError):
                stats["manifests_skipped"] += 1
                continue
            stats["manifests_parsed"] += 1
            rel = p.relative_to(repo).as_posix()
            for n in names:
                deps.setdefault((eco, n), Dependency(eco, n, rel))
    return list(deps.values()), stats
