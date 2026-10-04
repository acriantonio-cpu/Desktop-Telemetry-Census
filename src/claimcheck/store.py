"""Per-run SQLite store. Design goals: no information loss, no silent overwrite, resumable.

* Every phase execution is an *attempt* (phase, seq). Re-running a phase creates a NEW attempt.
* Result tables are APPEND-ONLY: SQL triggers abort any UPDATE/DELETE on them.
* Only `attempts` (status / excluded flag), `raw_files` (ingest progress) and `meta` are mutable.
* "Current" data is a *view* over attempts:
    - capture phases: every usable attempt (done/partial, not excluded) is merged;
    - analysis phases: the latest usable attempt wins (older ones stay queryable).
"""

from __future__ import annotations

import re
import sqlite3
import threading
import time
from pathlib import Path

from claimcheck.errors import ClaimCheckError
from claimcheck.models import CAPTURE_PHASES, DONE, INTERRUPTED, PARTIAL, RUNNING, USABLE_CAPTURE_STATUSES
from claimcheck.util import jdump, jload, utcnow_iso

SCHEMA_VERSION = 1

_TABLES = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS attempts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  phase TEXT NOT NULL, seq INTEGER NOT NULL, status TEXT NOT NULL,
  started_at TEXT NOT NULL, finished_at TEXT,
  excluded INTEGER NOT NULL DEFAULT 0,
  params TEXT, summary TEXT, note TEXT,
  UNIQUE(phase, seq));

CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, level TEXT NOT NULL,
  attempt_id INTEGER, message TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS raw_files(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  attempt_id INTEGER NOT NULL REFERENCES attempts(id),
  capture_phase TEXT NOT NULL,
  path TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  sha256 TEXT, size INTEGER,
  lines_ingested INTEGER NOT NULL DEFAULT 0,
  complete INTEGER NOT NULL DEFAULT 0);

CREATE TABLE IF NOT EXISTS flows(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  attempt_id INTEGER NOT NULL REFERENCES attempts(id),
  raw_file_id INTEGER NOT NULL REFERENCES raw_files(id),
  raw_line INTEGER NOT NULL,
  capture_phase TEXT NOT NULL,
  ts REAL, kind TEXT NOT NULL, host TEXT, sni TEXT, port INTEGER, scheme TEXT,
  method TEXT, path TEXT, query_keys TEXT, status_code INTEGER,
  req_bytes INTEGER, resp_bytes INTEGER, req_ct TEXT,
  payload_keys TEXT, id_hashes TEXT, sample TEXT, features TEXT,
  UNIQUE(raw_file_id, raw_line));
CREATE INDEX IF NOT EXISTS ix_flows_phase_host ON flows(capture_phase, host);

CREATE TABLE IF NOT EXISTS claims(
  id INTEGER PRIMARY KEY AUTOINCREMENT, attempt_id INTEGER NOT NULL REFERENCES attempts(id),
  kind TEXT NOT NULL, text TEXT NOT NULL, source_role TEXT, source_ref TEXT,
  confidence REAL, detail TEXT);

CREATE TABLE IF NOT EXISTS disclosed(
  id INTEGER PRIMARY KEY AUTOINCREMENT, attempt_id INTEGER NOT NULL REFERENCES attempts(id),
  sdk_id TEXT NOT NULL, source_ref TEXT, snippet TEXT);

CREATE TABLE IF NOT EXISTS static_evidence(
  id INTEGER PRIMARY KEY AUTOINCREMENT, attempt_id INTEGER NOT NULL REFERENCES attempts(id),
  side TEXT NOT NULL, sdk_id TEXT NOT NULL, kind TEXT NOT NULL, confidence REAL,
  location TEXT, detail TEXT);

CREATE TABLE IF NOT EXISTS dns_records(
  id INTEGER PRIMARY KEY AUTOINCREMENT, attempt_id INTEGER NOT NULL REFERENCES attempts(id),
  host TEXT NOT NULL, cname_chain TEXT, error TEXT, resolved_at TEXT);

CREATE TABLE IF NOT EXISTS labels(
  id INTEGER PRIMARY KEY AUTOINCREMENT, attempt_id INTEGER NOT NULL REFERENCES attempts(id),
  capture_phase TEXT NOT NULL, host TEXT NOT NULL, label TEXT NOT NULL, score REAL,
  sdk_id TEXT, category TEXT, n_flows INTEGER, req_bytes INTEGER,
  features TEXT, reasons TEXT);

CREATE TABLE IF NOT EXISTS verdicts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, attempt_id INTEGER NOT NULL REFERENCES attempts(id),
  check_id TEXT NOT NULL, claim_kind TEXT, verdict TEXT NOT NULL, severity TEXT,
  title TEXT, explanation TEXT, evidence TEXT);
"""

APPEND_ONLY = ["events", "flows", "claims", "disclosed", "static_evidence", "dns_records", "labels", "verdicts"]

_COLUMNS = {
    "flows": ["attempt_id", "raw_file_id", "raw_line", "capture_phase", "ts", "kind", "host", "sni", "port",
              "scheme", "method", "path", "query_keys", "status_code", "req_bytes", "resp_bytes", "req_ct",
              "payload_keys", "id_hashes", "sample", "features"],
    "claims": ["attempt_id", "kind", "text", "source_role", "source_ref", "confidence", "detail"],
    "disclosed": ["attempt_id", "sdk_id", "source_ref", "snippet"],
    "static_evidence": ["attempt_id", "side", "sdk_id", "kind", "confidence", "location", "detail"],
    "dns_records": ["attempt_id", "host", "cname_chain", "error", "resolved_at"],
    "labels": ["attempt_id", "capture_phase", "host", "label", "score", "sdk_id", "category", "n_flows",
               "req_bytes", "features", "reasons"],
    "verdicts": ["attempt_id", "check_id", "claim_kind", "verdict", "severity", "title", "explanation", "evidence"],
}
_JSON_COLUMNS = {"query_keys", "payload_keys", "id_hashes", "features", "detail", "cname_chain", "reasons", "evidence"}


def _triggers() -> str:
    out = []
    for t in APPEND_ONLY:
        out.append(
            f"CREATE TRIGGER IF NOT EXISTS {t}_no_update BEFORE UPDATE ON {t} "
            f"BEGIN SELECT RAISE(ABORT, 'append-only table: {t}'); END;"
        )
        out.append(
            f"CREATE TRIGGER IF NOT EXISTS {t}_no_delete BEFORE DELETE ON {t} "
            f"BEGIN SELECT RAISE(ABORT, 'append-only table: {t}'); END;"
        )
    out.append(
        "CREATE TRIGGER IF NOT EXISTS attempts_no_delete BEFORE DELETE ON attempts "
        "BEGIN SELECT RAISE(ABORT, 'attempts are never deleted'); END;"
    )
    out.append(
        "CREATE TRIGGER IF NOT EXISTS raw_files_no_delete BEFORE DELETE ON raw_files "
        "BEGIN SELECT RAISE(ABORT, 'raw_files rows are never deleted'); END;"
    )
    return "\n".join(out)


class StoreError(ClaimCheckError, RuntimeError):
    """Expected, user-facing store problem (the CLI prints it cleanly, without a traceback)."""


QUERY_TIMEOUT_S = 20.0
_ALLOWED_ACTIONS = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_RECURSIVE}


def _read_only_authorizer(action, arg1, arg2, dbname, source):
    """SQLite-level sandbox for `sql`/`show --where`: SELECT-family only (no ATTACH, PRAGMA writes, DML, extensions)."""
    if action in _ALLOWED_ACTIONS:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_PRAGMA and arg1 in ("table_info", "table_xinfo"):
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


class Store:
    def __init__(self, path: Path, readonly: bool = False):
        self.path = Path(path)
        self.readonly = readonly
        self._lock = threading.RLock()
        if readonly:
            if not self.path.exists():
                raise StoreError(f"store not found: {self.path}")
            uri = f"file:{self.path.as_posix()}?mode=ro"
            self.conn = sqlite3.connect(uri, uri=True, timeout=30, check_same_thread=False)
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(str(self.path), timeout=30, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        try:
            if not readonly:
                self.conn.execute("PRAGMA journal_mode=WAL")
                # FULL: attempt status / raw-file registration must survive a power cut (batches are large, cost is negligible)
                self.conn.execute("PRAGMA synchronous=FULL")
                self._init_schema()
            self.conn.execute("PRAGMA foreign_keys=ON")
        except sqlite3.DatabaseError as e:
            self.conn.close()
            raise StoreError(f"cannot open store {self.path}: {e}",
                             hint="'locked' = another claimcheck process is writing; 'not a database'/'malformed' = the file is damaged: "
                                  "restore it from a `claimcheck export` zip (raw/*.jsonl can be re-ingested).") from e

    # ---- lifecycle ------------------------------------------------------
    def _init_schema(self) -> None:
        with self._lock, self.conn:
            ver = self.conn.execute("PRAGMA user_version").fetchone()[0]
            if ver > SCHEMA_VERSION:
                raise StoreError(
                    f"store schema v{ver} is newer than this tool (v{SCHEMA_VERSION}); upgrade claimcheck"
                )
            self.conn.executescript(_TABLES + _triggers())
            if ver < SCHEMA_VERSION:
                self.conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")

    def close(self) -> None:
        try:
            self.conn.close()
        except sqlite3.Error:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ---- helpers --------------------------------------------------------
    def _rows(self, sql: str, params=()) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def _one(self, sql: str, params=()):
        with self._lock:
            r = self.conn.execute(sql, params).fetchone()
        return dict(r) if r else None

    # ---- meta -----------------------------------------------------------
    def set_meta(self, key: str, value) -> None:
        with self._lock, self.conn:
            self.conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)", (key, str(value)))

    def get_meta(self, key: str, default=None):
        r = self._one("SELECT value FROM meta WHERE key=?", (key,))
        return r["value"] if r else default

    # ---- attempts -------------------------------------------------------
    def begin_attempt(self, phase: str, params: dict | None = None) -> int:
        with self._lock, self.conn:
            self.conn.execute("BEGIN IMMEDIATE")  # take the write lock BEFORE reading MAX(seq): two processes can never pick the same seq
            seq = (self.conn.execute("SELECT COALESCE(MAX(seq),0)+1 FROM attempts WHERE phase=?", (phase,)).fetchone()[0])
            cur = self.conn.execute(
                "INSERT INTO attempts(phase,seq,status,started_at,params) VALUES(?,?,?,?,?)",
                (phase, seq, RUNNING, utcnow_iso(), jdump(params or {})),
            )
            return int(cur.lastrowid)

    def finish_attempt(self, attempt_id: int, status: str, summary: dict | None = None, note: str = "") -> None:
        with self._lock, self.conn:
            self.conn.execute(
                "UPDATE attempts SET status=?, finished_at=?, summary=?, note=? WHERE id=?",
                (status, utcnow_iso(), jdump(summary or {}), note, attempt_id),
            )

    def mark_stale_running(self) -> list[dict]:
        """Attempts left in 'running' by a crashed process. Caller must hold the run lock."""
        stale = self._rows("SELECT id, phase, seq FROM attempts WHERE status=?", (RUNNING,))
        if stale:
            with self._lock, self.conn:
                self.conn.execute(
                    "UPDATE attempts SET status=?, finished_at=?, note=COALESCE(note,'')||' [recovered: process died]' "
                    "WHERE status=?",
                    (INTERRUPTED, utcnow_iso(), RUNNING),
                )
        return stale

    def get_attempt(self, attempt_id: int) -> dict | None:
        r = self._one("SELECT * FROM attempts WHERE id=?", (attempt_id,))
        if r:
            r["params"] = jload(r["params"], {})
            r["summary"] = jload(r["summary"], {})
        return r

    def attempts(self, phase: str | None = None) -> list[dict]:
        sql, args = "SELECT * FROM attempts", ()
        if phase:
            sql, args = sql + " WHERE phase=?", (phase,)
        rows = self._rows(sql + " ORDER BY id", args)
        for r in rows:
            r["params"] = jload(r["params"], {})
            r["summary"] = jload(r["summary"], {})
        return rows

    def set_excluded(self, attempt_id: int, excluded: bool) -> bool:
        with self._lock, self.conn:
            cur = self.conn.execute("UPDATE attempts SET excluded=? WHERE id=?", (1 if excluded else 0, attempt_id))
            return cur.rowcount == 1

    def effective_attempt_ids(self, phase: str) -> list[int]:
        """Attempts whose data counts for downstream phases (see module docstring)."""
        if phase in CAPTURE_PHASES:
            marks = ",".join("?" for _ in USABLE_CAPTURE_STATUSES)
            rows = self._rows(
                f"SELECT id FROM attempts WHERE phase=? AND excluded=0 AND status IN ({marks}) ORDER BY id",  # noqa: S608  # placeholders only  # nosec B608
                (phase, *USABLE_CAPTURE_STATUSES),
            )
            return [r["id"] for r in rows]
        r = self._one(
            "SELECT id FROM attempts WHERE phase=? AND excluded=0 AND status=? ORDER BY id DESC LIMIT 1",
            (phase, DONE),
        )
        return [r["id"]] if r else []

    def phase_status(self, phase: str) -> dict:
        atts = self.attempts(phase)
        eff = self.effective_attempt_ids(phase)
        if not atts:
            return {"phase": phase, "status": "pending", "attempts": 0, "effective": [], "last": None}
        last = atts[-1]
        status = last["status"]
        if eff and status not in (RUNNING,):
            status = DONE if any(a["status"] == DONE and a["id"] in eff for a in atts) else PARTIAL
            if phase not in CAPTURE_PHASES and last["id"] != eff[-1] and last["status"] != DONE:
                status = f"{DONE} (latest attempt {last['status']})"
        return {"phase": phase, "status": status, "attempts": len(atts), "effective": eff, "last": last}

    # ---- events ---------------------------------------------------------
    def log(self, level: str, message: str, attempt_id: int | None = None) -> None:
        with self._lock, self.conn:
            self.conn.execute(
                "INSERT INTO events(ts,level,attempt_id,message) VALUES(?,?,?,?)",
                (utcnow_iso(), level, attempt_id, str(message)[:4000]),
            )

    def events(self, limit: int = 200, level: str | None = None) -> list[dict]:
        if level:
            return self._rows("SELECT * FROM events WHERE level=? ORDER BY id DESC LIMIT ?", (level, limit))[::-1]
        return self._rows("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))[::-1]

    # ---- raw files ------------------------------------------------------
    def register_raw_file(self, attempt_id: int, capture_phase: str, relpath: str) -> int:
        with self._lock, self.conn:
            cur = self.conn.execute(
                "INSERT INTO raw_files(attempt_id,capture_phase,path,created_at) VALUES(?,?,?,?)",
                (attempt_id, capture_phase, relpath, utcnow_iso()),
            )
            return int(cur.lastrowid)

    def raw_files(self, attempt_id: int | None = None, only_incomplete: bool = False) -> list[dict]:
        sql, args, cond = "SELECT * FROM raw_files", [], []
        if attempt_id is not None:
            cond.append("attempt_id=?")
            args.append(attempt_id)
        if only_incomplete:
            cond.append("complete=0")
        if cond:
            sql += " WHERE " + " AND ".join(cond)
        return self._rows(sql + " ORDER BY id", tuple(args))

    def update_raw_file(self, raw_id: int, **fields_) -> None:
        allowed = {"sha256", "size", "lines_ingested", "complete"}
        bad = set(fields_) - allowed
        if bad:
            raise StoreError(f"cannot update raw_files columns {bad}")
        sets = ",".join(f"{k}=?" for k in fields_)
        with self._lock, self.conn:
            self.conn.execute(f"UPDATE raw_files SET {sets} WHERE id=?", (*fields_.values(), raw_id))  # noqa: S608  # identifiers come from internal allow-lists / '?' placeholders  # nosec B608

    # ---- bulk insert ----------------------------------------------------
    def insert_many(self, table: str, rows: list[dict], ignore_dups: bool = False) -> int:
        if not rows:
            return 0
        cols = _COLUMNS[table]
        data = []
        for r in rows:
            vals = []
            for c in cols:
                v = r.get(c)
                if c in _JSON_COLUMNS and not isinstance(v, (str, type(None))):
                    v = jdump(v)
                vals.append(v)
            data.append(vals)
        verb = "INSERT OR IGNORE" if ignore_dups else "INSERT"
        sql = f"{verb} INTO {table}({','.join(cols)}) VALUES({','.join('?' for _ in cols)})"  # noqa: S608  # identifiers come from internal allow-lists / '?' placeholders  # nosec B608
        with self._lock, self.conn:
            before = self.conn.total_changes
            self.conn.executemany(sql, data)
            return self.conn.total_changes - before

    # ---- typed readers (JSON columns decoded) ---------------------------
    def select(self, table: str, attempt_ids: list[int] | None = None, where: str = "", params=(), order: str = "id") -> list[dict]:
        if table not in _COLUMNS and table not in ("attempts", "events", "raw_files"):
            raise StoreError(f"unknown table {table}")
        if not re.fullmatch(r"[a-z_]+( (ASC|DESC))?", order, re.I):
            raise StoreError(f"invalid ORDER BY: {order!r}")
        conds, args = [], list(params)
        if attempt_ids is not None:
            if not attempt_ids:
                return []
            conds.append(f"attempt_id IN ({','.join('?' for _ in attempt_ids)})")
            args = list(attempt_ids) + args
        if where:
            conds.append(f"({where})")
        sql = f"SELECT * FROM {table}"  # noqa: S608  # identifiers come from internal allow-lists / '?' placeholders  # nosec B608
        if conds:
            sql += " WHERE " + " AND ".join(conds)
        sql += f" ORDER BY {order}"
        rows = self._rows(sql, tuple(args))
        for r in rows:
            for c in _JSON_COLUMNS:
                if c in r:
                    r[c] = jload(r[c], [] if c in ("query_keys", "payload_keys", "id_hashes", "reasons", "cname_chain") else {})
        return rows

    def flows_for_classification(self, attempt_ids: list[int]) -> list[dict]:
        """Lean projection (no payload samples / features): keeps RAM low for large captures."""
        if not attempt_ids:
            return []
        marks = ",".join("?" for _ in attempt_ids)
        rows = self._rows(
            "SELECT capture_phase, kind, host, sni, method, path, ts, req_bytes, payload_keys, id_hashes "  # noqa: S608
            f"FROM flows WHERE attempt_id IN ({marks}) ORDER BY id",  # only '?' placeholders are interpolated  # nosec B608
            tuple(attempt_ids),
        )
        for r in rows:
            r["payload_keys"] = jload(r["payload_keys"], [])
            r["id_hashes"] = jload(r["id_hashes"], [])
        return rows

    def counts(self) -> dict:
        out = {}
        for t in ["flows", "claims", "disclosed", "static_evidence", "dns_records", "labels", "verdicts", "events", "attempts", "raw_files"]:
            out[t] = self._one(f"SELECT COUNT(*) AS n FROM {t}")["n"]  # noqa: S608  # identifiers come from internal allow-lists / '?' placeholders  # nosec B608
        return out

    def query_readonly(self, sql: str, limit: int = 500, timeout_s: float = QUERY_TIMEOUT_S) -> tuple[list[str], list[tuple]]:
        """Debug helper: run ONE read-only statement on a separate read-only connection (authorizer sandbox + time limit)."""
        stmt = sql.strip().rstrip(";")
        if not stmt.lower().startswith(("select", "with", "pragma table_info", "explain")):
            raise StoreError("only SELECT / WITH queries are allowed")
        ro = Store(self.path, readonly=True)
        deadline = time.monotonic() + timeout_s
        ro.conn.set_authorizer(_read_only_authorizer)
        ro.conn.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 2000)
        try:
            cur = ro.conn.execute(stmt)
            cols = [d[0] for d in (cur.description or [])]
            return cols, [tuple(r) for r in cur.fetchmany(limit)]
        except sqlite3.ProgrammingError as e:  # "You can only execute one statement at a time"
            raise StoreError(f"only a single statement is allowed ({e})") from e
        except sqlite3.OperationalError as e:
            if "interrupted" in str(e).lower():
                raise StoreError(f"query stopped after {timeout_s:.0f} s (too expensive): add LIMIT / WHERE or simplify it") from e
            raise StoreError(f"SQL error: {e}") from e
        except sqlite3.DatabaseError as e:  # authorizer denial ("not authorized") and friends
            raise StoreError(f"query refused: {e}") from e
        finally:
            ro.close()


__all__ = ["Store", "StoreError", "PARTIAL"]
