"""Minimal, read-only parser for Electron .asar archives (no extraction to disk => no zip-slip class bugs).

Format: [u32=4][u32 header_pickle_size][u32 payload_size][u32 json_len][json ...][file data...]
File data starts at offset 8 + header_pickle_size; each file entry has `size` and string `offset`.
"""

from __future__ import annotations

import json
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

MAX_HEADER = 64 * 1024 * 1024  # refuse absurd headers (corrupt/malicious files)
MAX_ENTRIES = 500_000  # a 64 MB header can describe millions of files: bound the work


class AsarError(ValueError):
    pass


@dataclass
class AsarEntry:
    path: str
    size: int
    offset: int  # absolute offset inside the archive file
    unpacked: bool = False


def read_header(path: Path) -> tuple[dict, int]:
    with open(path, "rb") as f:
        head = f.read(16)
        if len(head) < 16:
            raise AsarError("file too small to be an asar archive")
        marker, header_size, _payload, json_len = struct.unpack("<IIII", head)
        if marker != 4 or header_size < 8 or header_size > MAX_HEADER or json_len > header_size:
            raise AsarError("not an asar archive (bad header)")
        raw = f.read(json_len)
        if len(raw) != json_len:
            raise AsarError("truncated asar header")
    try:
        return json.loads(raw.decode("utf-8")), 8 + header_size
    except (UnicodeDecodeError, ValueError) as e:
        raise AsarError(f"asar header is not valid JSON: {e}") from e


def iter_entries(path: Path) -> Iterator[AsarEntry]:
    header, base = read_header(path)
    file_size = Path(path).stat().st_size
    stack = [("", header)]
    yielded = 0
    while stack:
        prefix, node = stack.pop()
        files = node.get("files") if isinstance(node, dict) else None
        if not isinstance(files, dict):
            continue
        for name, child in files.items():
            if not isinstance(child, dict):
                continue  # corrupt node: skip it, never let one bad entry abort the whole archive
            rel = f"{prefix}/{name}" if prefix else str(name)
            if "files" in child:
                stack.append((rel, child))
                continue
            try:
                size = int(child.get("size", 0))
                unpacked = bool(child.get("unpacked"))
                off = base + int(child.get("offset", 0))
            except (TypeError, ValueError, OverflowError):
                continue
            if not unpacked and (size < 0 or off + size > file_size):
                continue  # corrupt entry: skip, never read outside the archive
            yielded += 1
            if yielded > MAX_ENTRIES:
                raise AsarError(f"asar lists more than {MAX_ENTRIES} entries: refusing to walk it")
            yield AsarEntry(rel, size, off, unpacked)


def read_entry(path: Path, entry: AsarEntry, chunk: int) -> Iterator[bytes]:
    if entry.unpacked:
        return
    with open(path, "rb") as f:
        f.seek(entry.offset)
        remaining = entry.size
        while remaining > 0:
            block = f.read(min(chunk, remaining))
            if not block:
                break
            remaining -= len(block)
            yield block
