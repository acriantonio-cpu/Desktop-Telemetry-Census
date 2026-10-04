"""Execution context: opens a run (lock + store + manifest), wires logging, recovers from crashes."""

from __future__ import annotations

import contextlib
import traceback
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from claimcheck.manifest import Manifest
from claimcheck.runs import RunDir, RunLock, load_run_manifest, manifest_hash, resolve_run
from claimcheck.signatures import SignatureSet, load_signatures
from claimcheck.store import Store
from claimcheck.ui import ui
from claimcheck.util import utcnow_iso


@dataclass
class Context:
    run: RunDir
    store: Store
    manifest: Manifest
    manifest_sha256: str = ""
    writable: bool = True
    current_attempt: int | None = None
    stale: list = field(default_factory=list)  # attempts found 'running' at open (crash recovery)
    _sigs: SignatureSet | None = field(default=None, repr=False)

    # ---- signatures (bundled + manifest extras), loaded lazily ------------
    @property
    def sigs(self) -> SignatureSet:
        if self._sigs is None:
            self._sigs = load_signatures(self.manifest.static.extra_signatures)
            if self._sigs.overridden:
                ui.warn("static.extra_signatures replace bundled vendor(s): " + ", ".join(self._sigs.overridden))
        return self._sigs

    # ---- journaling: INFO+ -> events table, everything -> log file ---------
    def journal(self, level: str, message: str) -> None:
        line = f"{utcnow_iso()} {level:<7} {message}\n"
        if self.writable:
            try:
                self.run.logs_dir.mkdir(parents=True, exist_ok=True)
                with open(self.run.logs_dir / "claimcheck.log", "a", encoding="utf-8", newline="\n") as f:
                    f.write(line)
            except OSError:
                pass
            if level in ("STEP", "INFO", "OK", "WARN", "ERROR"):
                self.store.log(level, message, self.current_attempt)


@contextlib.contextmanager
def open_context(runs_root: Path, app: str | None, run: str | None, write: bool = True, verbosity: int = 0) -> Iterator[Context]:
    """Open a run. write=True takes the exclusive lock, recovers crashed attempts and enables journaling."""
    ui.set_verbosity(verbosity)
    rd = resolve_run(runs_root, app, run)
    lock = RunLock(rd)
    if write:
        lock.acquire()
    store = None
    try:
        manifest = load_run_manifest(rd)
        store = Store(rd.store_path, readonly=not write)
        ctx = Context(run=rd, store=store, manifest=manifest, manifest_sha256=manifest_hash(rd), writable=write)
        if write:
            ui.attach_journal(ctx.journal)
            if lock.reclaimed_from:
                ui.warn(f"reclaimed a stale lock left by PID {lock.reclaimed_from.get('pid')} (process is gone)")
            for w in manifest.warnings:
                ui.warn(f"manifest: {w}")
            stale = store.mark_stale_running()
            ctx.stale = stale
            for s in stale:
                ui.warn(f"attempt {s['phase']} #{s['seq']} was interrupted by a crash/kill: marked 'interrupted' (data kept)")
        yield ctx
    except BaseException as e:
        if write and store is not None and not isinstance(e, (KeyboardInterrupt, SystemExit)):
            with contextlib.suppress(Exception):
                store.log("ERROR", "".join(traceback.format_exception_only(type(e), e)).strip())
        raise
    finally:
        ui.attach_journal(None)
        if store is not None:
            store.close()
        lock.release()
