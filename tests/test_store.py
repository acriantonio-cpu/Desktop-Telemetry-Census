from __future__ import annotations

import sqlite3

import pytest

from claimcheck.store import Store, StoreError


@pytest.fixture()
def st(tmp_path):
    s = Store(tmp_path / "s.sqlite")
    yield s
    s.close()


def _claim(a, text="x"):
    return {"attempt_id": a, "kind": "no_telemetry", "text": text, "confidence": 0.8, "detail": {"q": []}}


@pytest.mark.parametrize("table,stmt", [
    ("claims", "DELETE FROM claims"), ("claims", "UPDATE claims SET text='y'"),
    ("flows", "DELETE FROM flows"), ("verdicts", "UPDATE verdicts SET verdict='X'"),
    ("labels", "DELETE FROM labels"), ("events", "DELETE FROM events"), ("static_evidence", "UPDATE static_evidence SET sdk_id='z'"),
])
def test_result_tables_are_append_only(st, table, stmt):
    a = st.begin_attempt("claims")
    rid = st.register_raw_file(a, "capture_idle", "raw/a.jsonl")
    st.insert_many("claims", [_claim(a)])
    st.insert_many("flows", [{"attempt_id": a, "raw_file_id": rid, "raw_line": 1, "capture_phase": "capture_idle", "kind": "http", "host": "h"}])
    st.insert_many("verdicts", [{"attempt_id": a, "check_id": "c", "verdict": "WARNING"}])
    st.insert_many("labels", [{"attempt_id": a, "capture_phase": "capture_idle", "host": "h", "label": "unknown"}])
    st.insert_many("static_evidence", [{"attempt_id": a, "side": "binary", "sdk_id": "sentry", "kind": "sdk_string"}])
    st.log("INFO", "hello")
    # SQLite triggers are row-level, so every table needs at least one row for the guard to fire
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        st.conn.execute(stmt)


def test_attempts_and_raw_files_cannot_be_deleted(st):
    a = st.begin_attempt("claims")
    rid = st.register_raw_file(a, "capture_idle", "raw/x.jsonl")
    for stmt in ("DELETE FROM attempts", "DELETE FROM raw_files"):
        with pytest.raises(sqlite3.DatabaseError):
            st.conn.execute(stmt)
    assert rid


def test_rerun_creates_new_attempt_and_latest_wins_for_analysis_phases(st):
    a1 = st.begin_attempt("claims")
    st.insert_many("claims", [_claim(a1, "old")])
    st.finish_attempt(a1, "done")
    a2 = st.begin_attempt("claims")
    st.insert_many("claims", [_claim(a2, "new")])
    st.finish_attempt(a2, "done")
    assert st.effective_attempt_ids("claims") == [a2]
    assert {c["text"] for c in st.select("claims", [a2])} == {"new"}
    assert {c["text"] for c in st.select("claims")} == {"old", "new"}  # nothing lost
    assert [a["seq"] for a in st.attempts("claims")] == [1, 2]


def test_failed_attempt_does_not_replace_good_one(st):
    a1 = st.begin_attempt("static")
    st.finish_attempt(a1, "done")
    a2 = st.begin_attempt("static")
    st.finish_attempt(a2, "failed", note="boom")
    assert st.effective_attempt_ids("static") == [a1]


def test_capture_attempts_are_merged_and_excludable(st):
    ids = []
    for status in ("done", "partial", "failed", "done"):
        a = st.begin_attempt("capture_idle")
        st.finish_attempt(a, status)
        ids.append(a)
    assert st.effective_attempt_ids("capture_idle") == [ids[0], ids[1], ids[3]]
    st.set_excluded(ids[1], True)
    assert st.effective_attempt_ids("capture_idle") == [ids[0], ids[3]]
    st.set_excluded(ids[1], False)
    assert ids[1] in st.effective_attempt_ids("capture_idle")


def test_stale_running_attempts_are_recovered(st):
    a = st.begin_attempt("capture_use")
    stale = st.mark_stale_running()
    assert [s["id"] for s in stale] == [a]
    att = st.get_attempt(a)
    assert att["status"] == "interrupted" and "recovered" in att["note"]
    assert st.mark_stale_running() == []


def test_insert_ignore_duplicates_is_idempotent(st):
    a = st.begin_attempt("capture_idle")
    rid = st.register_raw_file(a, "capture_idle", "raw/a.jsonl")
    row = {"attempt_id": a, "raw_file_id": rid, "raw_line": 1, "capture_phase": "capture_idle", "kind": "http", "host": "h"}
    assert st.insert_many("flows", [row], ignore_dups=True) == 1
    assert st.insert_many("flows", [row], ignore_dups=True) == 0
    assert st.counts()["flows"] == 1


def test_json_columns_roundtrip(st):
    a = st.begin_attempt("classify")
    st.insert_many("labels", [{"attempt_id": a, "capture_phase": "capture_idle", "host": "h", "label": "unknown", "score": 0.1,
                               "features": {"k": [1]}, "reasons": ["r1", "r2"]}])
    row = st.select("labels")[0]
    assert row["features"] == {"k": [1]} and row["reasons"] == ["r1", "r2"]


def test_query_readonly_blocks_writes_and_multi_statements(st):
    st.set_meta("k", "v")
    cols, rows = st.query_readonly("SELECT key, value FROM meta")
    assert cols == ["key", "value"] and rows == [("k", "v")]
    for bad in ("DELETE FROM meta", "SELECT 1; DROP TABLE meta", "INSERT INTO meta VALUES('a','b')", "PRAGMA user_version=5"):
        with pytest.raises(StoreError):
            st.query_readonly(bad)
    assert st.get_meta("k") == "v"


def test_readonly_store_cannot_write(tmp_path):
    Store(tmp_path / "s.sqlite").close()
    ro = Store(tmp_path / "s.sqlite", readonly=True)
    with pytest.raises(sqlite3.OperationalError):
        ro.conn.execute("INSERT INTO meta VALUES('a','b')")
    ro.close()
    with pytest.raises(StoreError):
        Store(tmp_path / "missing.sqlite", readonly=True)


def test_update_raw_file_rejects_unknown_columns(st):
    a = st.begin_attempt("capture_idle")
    rid = st.register_raw_file(a, "capture_idle", "raw/a.jsonl")
    with pytest.raises(StoreError):
        st.update_raw_file(rid, path="evil")
    st.update_raw_file(rid, lines_ingested=5, complete=1)
    assert st.raw_files()[0]["lines_ingested"] == 5


def test_newer_schema_is_refused(tmp_path):
    p = tmp_path / "s.sqlite"
    Store(p).close()
    con = sqlite3.connect(p)
    con.execute("PRAGMA user_version=99")
    con.close()
    with pytest.raises(StoreError, match="newer"):
        Store(p)


def test_select_rejects_unknown_table(st):
    with pytest.raises(StoreError):
        st.select("sqlite_master")
