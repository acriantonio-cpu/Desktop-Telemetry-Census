"""Command line interface (Typer). One command per phase + inspection/maintenance commands."""

from __future__ import annotations

import contextlib
import json
import sqlite3
import sys
import webbrowser
import zipfile
from pathlib import Path
from typing import Annotated

import typer

from claimcheck import __version__
from claimcheck.benchmark import evaluate, load_truth, observed_from_store
from claimcheck.candidates import get_candidate, list_candidates, manifest_text_for
from claimcheck.classify.blocklists import DEFAULT_LISTS_DIR, fetch_default_lists
from claimcheck.context import open_context
from claimcheck.dynamic.capture import addon_path, run_capture
from claimcheck.dynamic.importer import import_flows
from claimcheck.dynamic.ingest import verify_raw_files
from claimcheck.errors import ClaimCheckError
from claimcheck.manifest import load_manifest, render_template
from claimcheck.models import SHORT_TO_PHASE
from claimcheck.pipeline import (
    next_actions, phase_claims, phase_classify, phase_report, phase_score, phase_static, recover_orphans, resume,
    run_phase, status_rows,
)
from claimcheck.resources import doctor_checks
from claimcheck.runs import RunDir, create_run, list_runs, resolve_run
from claimcheck.store import Store
from claimcheck.ui import ui
from claimcheck.util import human_bytes, slugify, truncate, unique_path

app = typer.Typer(help="ClaimCheck - do privacy claims match observed behaviour? (see docs/)", no_args_is_help=True,
                  add_completion=False, pretty_exceptions_enable=False)

RunsRoot = Annotated[Path, typer.Option("--runs-root", envvar="CLAIMCHECK_RUNS", help="Folder that contains all runs.")]
AppOpt = Annotated[str | None, typer.Option("--app", "-a", help="App slug (needed only if several apps exist).")]
RunOpt = Annotated[str | None, typer.Option("--run", "-r", help="Run id or 'latest' (default).")]
Verbose = Annotated[int, typer.Option("--verbose", "-v", count=True, help="-v detail, -vv debug traces.")]
Debug = Annotated[bool, typer.Option("--debug", help="Show tracebacks + debug traces (same as -vv).")]
_STATE = {"debug": False}
ROOT = Path("runs")


def _ctx(runs_root, app_, run, verbose, debug, write=True):
    _STATE["debug"] = debug
    ctx_mgr = open_context(runs_root, app_, run, write=write, verbosity=2 if debug else verbose)
    return ctx_mgr


def _header(ctx) -> None:
    ui.info(f"app={ctx.run.app_slug}  run={ctx.run.run_id}  ({ctx.run.path})")


def _next(ctx) -> None:
    tips = next_actions(ctx)
    if tips:
        ui.plain("\nNext steps:")
        for t in tips[:3]:
            ui.plain("  " + t)


# ------------------------------------------------------------------ setup / info
@app.command()
def version() -> None:
    """Print version."""
    ui.plain(f"claimcheck {__version__}")


@app.command()
def doctor(runs_root: RunsRoot = ROOT, online: Annotated[bool, typer.Option("--online", help="Also test internet access.")] = False,
           mitmdump: Annotated[str, typer.Option(help="mitmdump command to check.")] = "mitmdump") -> None:
    """Check Python, privileges, CPU/RAM/disk, mitmproxy, git. Run this first."""
    checks = doctor_checks(runs_root, mitmdump, online)
    ui.table("environment check", ["check", "status", "detail", "advice"], [[c.name, c.status, c.detail, c.advice] for c in checks])
    bad = [c for c in checks if c.status == "FAIL"]
    if bad:
        ui.error("blocking problems found: " + ", ".join(c.name for c in bad))
        raise typer.Exit(2)
    warns = [c for c in checks if c.status == "WARN"]
    (ui.warn if warns else ui.ok)(f"{len(warns)} warning(s)" if warns else "environment looks good")


@app.command()
def new(name: Annotated[str, typer.Argument(help="App name")], out: Annotated[Path | None, typer.Option("--out", "-o")] = None) -> None:
    """Create a blank manifest template (apps/<slug>.yaml). Never overwrites."""
    path = out or Path("apps") / f"{slugify(name)}.yaml"
    if path.exists():
        raise ClaimCheckError(f"{path} already exists (not overwritten)", hint="Choose another --out or edit the existing file.")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_template(name), encoding="utf-8", newline="\n")
    ui.ok(f"template written: {path}")
    ui.info("edit it, then: claimcheck init " + str(path))


@app.command()
def candidates(
    tier: Annotated[str | None, typer.Option(help="A (pilot) or B (extension)")] = None,
    role: Annotated[str | None, typer.Option(help="synthetic_control | control_negative | control_positive | claim_test")] = None,
    show: Annotated[str | None, typer.Option(help="Show details of one candidate (slug)")] = None,
    make: Annotated[str | None, typer.Option(help="Write apps/<slug>.yaml manifest for a candidate")] = None,
    out: Annotated[Path | None, typer.Option("--out", "-o")] = None,
) -> None:
    """List the built-in catalogue of apps to test, or generate a ready manifest for one."""
    if show:
        a = get_candidate(show)
        ui.kv(a["name"], [(k, json.dumps(v, ensure_ascii=False) if isinstance(v, (list, dict)) else v) for k, v in a.items()])
        return
    if make:
        text = manifest_text_for(make)
        path = out or Path("apps") / f"{make}.yaml"
        if path.exists():
            raise ClaimCheckError(f"{path} already exists (not overwritten)")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
        ui.ok(f"manifest written: {path}")
        ui.info("complete the TODO lines at the top (version, install_dir, repo_path, exe_name), then: claimcheck init " + str(path))
        return
    rows = list_candidates(tier, role)
    ui.table("candidate apps (starting point - verify claims yourself)", ["slug", "tier", "role", "stack", "status", "why"],
             [[a["slug"], a["tier"], a["role"], a.get("stack", ""), a.get("status", ""), truncate(a.get("why", ""), 70)] for a in rows])
    ui.info("details: claimcheck candidates --show <slug>   |   manifest: claimcheck candidates --make <slug>")


@app.command("fetch-lists")
def fetch_lists(dest: Annotated[Path, typer.Option(help="Where to store blocklists")] = DEFAULT_LISTS_DIR) -> None:
    """Download the Disconnect tracker list (optional; improves classification). Never overwrites."""
    for p in fetch_default_lists(dest):
        ui.ok(f"saved {p} ({human_bytes(p.stat().st_size)}). Licence of third-party lists: check upstream before redistributing.")


@app.command("addon-path")
def addon_path_cmd() -> None:
    """Print the mitmproxy addon path (useful to run mitmdump by hand for debugging)."""
    ui.plain(str(addon_path()))


# ------------------------------------------------------------------ runs
@app.command()
def init(manifest: Annotated[Path, typer.Argument(help="App manifest YAML")], runs_root: RunsRoot = ROOT,
         label: Annotated[str, typer.Option(help="Free text label for this run")] = "",
         verbose: Verbose = 0, debug: Debug = False) -> None:
    """Create a NEW run for an app (never touches existing runs)."""
    _STATE["debug"] = debug
    ui.set_verbosity(2 if debug else verbose)
    m = load_manifest(manifest)
    for w in m.warnings:
        ui.warn(f"manifest: {w}")
    rd = create_run(runs_root, manifest, label)
    ui.ok(f"run created: {rd.path}")
    ui.info("the manifest copy inside the run folder is the one used from now on (edit it there if needed)")
    ui.plain("\nNext steps:")
    ui.plain(f"  claimcheck --app {rd.app_slug} status    (or just: claimcheck status)")
    ui.plain("  claimcheck claims")
    ui.plain("  claimcheck static")


@app.command()
def runs(runs_root: RunsRoot = ROOT, app_: AppOpt = None) -> None:
    """List all runs (latest is marked with *)."""
    rows = list_runs(runs_root, app_)
    if not rows:
        ui.warn(f"no runs under {runs_root}. Create one with: claimcheck init apps/<app>.yaml")
        return
    ui.table("runs", ["", "app", "run id", "created", "label"], [["*" if r["latest"] else "", r["app"], r["run_id"], r["created_at"], r["label"]] for r in rows])


@app.command()
def status(runs_root: RunsRoot = ROOT, app_: AppOpt = None, run: RunOpt = None, verbose: Verbose = 0, debug: Debug = False) -> None:
    """Show phase status, data counts and what to do next (read-only, safe anytime)."""
    with _ctx(runs_root, app_, run, verbose, debug, write=False) as ctx:
        _header(ctx)
        ui.table("phases", ["phase", "status", "attempts", "counted attempt ids", "last started", "note"],
                 [[r["phase"] + (" (optional)" if r["optional"] else ""), r["status"], r["attempts"], r["effective"], r["last_started"], truncate(r["note"], 50)] for r in status_rows(ctx)])
        c = ctx.store.counts()
        ui.info("stored rows: " + ", ".join(f"{k}={v}" for k, v in c.items() if v))
        pending = ctx.store.raw_files(only_incomplete=True)
        if pending:
            ui.warn(f"{len(pending)} raw file(s) not fully ingested: any write command (or `claimcheck ingest`) will recover them")
        _next(ctx)


# ------------------------------------------------------------------ phases
def _run_simple(phase: str, fn, runs_root, app_, run, verbose, debug, **extra) -> None:
    with _ctx(runs_root, app_, run, verbose, debug) as ctx:
        _header(ctx)
        recover_orphans(ctx)
        run_phase(ctx, phase, lambda a: fn(ctx, a, **extra))
        _next(ctx)


@app.command()
def claims(runs_root: RunsRoot = ROOT, app_: AppOpt = None, run: RunOpt = None, verbose: Verbose = 0, debug: Debug = False) -> None:
    """Load README/homepage/privacy policy and extract the privacy claims."""
    _run_simple("claims", phase_claims, runs_root, app_, run, verbose, debug)


@app.command("static")
def static_cmd(side: Annotated[str, typer.Option(help="binary | repo | both")] = "both", runs_root: RunsRoot = ROOT, app_: AppOpt = None,
               run: RunOpt = None, verbose: Verbose = 0, debug: Debug = False) -> None:
    """Scan the installed app (binary) and the source repo for telemetry SDKs."""
    if side not in ("binary", "repo", "both"):
        raise ClaimCheckError("--side must be binary, repo or both")
    sides = {"binary", "repo"} if side == "both" else {side}
    _run_simple("static", phase_static, runs_root, app_, run, verbose, debug, sides=sides)


@app.command()
def capture(
    phase: Annotated[str, typer.Option(help="idle | use | optout")],
    minutes: Annotated[float | None, typer.Option(help="Override duration (0 = until Ctrl+C)")] = None,
    launch: Annotated[bool | None, typer.Option("--launch/--no-launch", help="Let claimcheck start the app (needs app.exe_path)")] = None,
    allow_no_admin: Annotated[bool, typer.Option(help="Try local capture without Administrator (usually fails)")] = False,
    runs_root: RunsRoot = ROOT, app_: AppOpt = None, run: RunOpt = None, verbose: Verbose = 0, debug: Debug = False,
) -> None:
    """Observe the app's network traffic with mitmproxy (interactive phase)."""
    if phase not in SHORT_TO_PHASE:
        raise ClaimCheckError("--phase must be one of: idle, use, optout")
    ph = SHORT_TO_PHASE[phase]
    with _ctx(runs_root, app_, run, verbose, debug) as ctx:
        _header(ctx)
        recover_orphans(ctx)
        run_phase(ctx, ph, lambda a: run_capture(ctx, a, ph, minutes, launch, allow_no_admin), {"minutes": minutes, "launch": launch})
        _next(ctx)


@app.command("import-flows")
def import_flows_cmd(file: Annotated[Path, typer.Argument(help="JSONL (claimcheck) or HAR file")],
                     phase: Annotated[str, typer.Option(help="idle | use | optout")] = "use",
                     fmt: Annotated[str, typer.Option("--format", help="jsonl | har")] = "har",
                     runs_root: RunsRoot = ROOT, app_: AppOpt = None, run: RunOpt = None, verbose: Verbose = 0, debug: Debug = False) -> None:
    """Import traffic captured with another tool (HAR from browser/Fiddler/Charles, or claimcheck JSONL)."""
    if phase not in SHORT_TO_PHASE:
        raise ClaimCheckError("--phase must be one of: idle, use, optout")
    ph = SHORT_TO_PHASE[phase]
    from claimcheck.pipeline import _log

    with _ctx(runs_root, app_, run, verbose, debug) as ctx:
        _header(ctx)

        def fn(attempt_id):
            from claimcheck.models import PhaseResult

            info = import_flows(ctx, ph, file, fmt, attempt_id, _log(ctx))
            n = sum(s["inserted"] for s in info["ingest"])
            ui.ok(f"imported {n} records into phase '{phase}'")
            return PhaseResult("done", {**info, "records": n}, note=f"imported from {file.name}")

        run_phase(ctx, ph, fn, {"import": str(file)})
        _next(ctx)


@app.command()
def ingest(runs_root: RunsRoot = ROOT, app_: AppOpt = None, run: RunOpt = None, verbose: Verbose = 0, debug: Debug = False) -> None:
    """Re-ingest raw capture files (recovery after a crash; idempotent, no duplicates)."""
    with _ctx(runs_root, app_, run, verbose, debug) as ctx:
        _header(ctx)
        n = recover_orphans(ctx)
        if not n and not ctx.store.raw_files(only_incomplete=True):
            ui.ok("nothing to ingest: all raw files are already in the store")


@app.command()
def classify(runs_root: RunsRoot = ROOT, app_: AppOpt = None, run: RunOpt = None, verbose: Verbose = 0, debug: Debug = False) -> None:
    """Classify observed hosts (telemetry / suspect / first-party ...) with reasons."""
    _run_simple("classify", phase_classify, runs_root, app_, run, verbose, debug)


@app.command()
def score(runs_root: RunsRoot = ROOT, app_: AppOpt = None, run: RunOpt = None, verbose: Verbose = 0, debug: Debug = False) -> None:
    """Confront every claim with the evidence and produce verdicts."""
    _run_simple("score", phase_score, runs_root, app_, run, verbose, debug)


@app.command()
def report(open_: Annotated[bool, typer.Option("--open", help="Open the HTML report in the browser")] = False,
           runs_root: RunsRoot = ROOT, app_: AppOpt = None, run: RunOpt = None, verbose: Verbose = 0, debug: Debug = False) -> None:
    """Write the HTML + JSON report (new file each time, nothing overwritten)."""
    with _ctx(runs_root, app_, run, verbose, debug) as ctx:
        _header(ctx)
        res = run_phase(ctx, "report", lambda a: phase_report(ctx, a))
        if open_:
            webbrowser.open(Path(res.summary["html"]).resolve().as_uri())


@app.command("resume")
def resume_cmd(with_capture: Annotated[bool, typer.Option("--with-capture", help="Also run missing capture phases (interactive)")] = False,
               runs_root: RunsRoot = ROOT, app_: AppOpt = None, run: RunOpt = None, verbose: Verbose = 0, debug: Debug = False) -> None:
    """Continue a run: execute every automatic phase that is missing, failed or stale."""
    with _ctx(runs_root, app_, run, verbose, debug) as ctx:
        _header(ctx)
        recover_orphans(ctx)
        ran = resume(ctx, with_capture)
        ui.ok("phases executed: " + (", ".join(ran) if ran else "none (everything is up to date)"))
        _next(ctx)


@app.command("run")
def run_cmd(manifest: Annotated[Path, typer.Argument()], runs_root: RunsRoot = ROOT, label: str = "",
            verbose: Verbose = 0, debug: Debug = False) -> None:
    """Shortcut: init + all automatic phases (claims, static, classify, score, report) for what is available."""
    _STATE["debug"] = debug
    rd = create_run(runs_root, manifest, label)
    ui.ok(f"run created: {rd.path}")
    with open_context(runs_root, rd.app_slug, rd.run_id, True, 2 if debug else verbose) as ctx:
        resume(ctx, with_capture=False)
        _next(ctx)


# ------------------------------------------------------------------ inspection / maintenance
_SHOW_COLS = {
    "flows": "id,attempt_id,capture_phase,kind,host,method,path,status_code,req_bytes,payload_keys",
    "labels": "id,capture_phase,host,label,score,sdk_id,n_flows,req_bytes",
    "verdicts": "id,check_id,claim_kind,verdict,severity,title",
    "claims": "id,kind,confidence,source_role,text",
    "static_evidence": "id,side,sdk_id,kind,confidence,location",
    "disclosed": "id,sdk_id,source_ref,snippet",
    "dns_records": "id,host,cname_chain,error",
    "attempts": "id,phase,seq,status,excluded,started_at,finished_at,note",
    "events": "id,ts,level,attempt_id,message",
    "raw_files": "id,attempt_id,capture_phase,path,size,lines_ingested,complete",
}


@app.command()
def show(table: Annotated[str, typer.Argument(help="flows|labels|verdicts|claims|static_evidence|disclosed|dns_records|attempts|events|raw_files")],
         limit: Annotated[int, typer.Option(help="Max rows (newest first)")] = 30,
         where: Annotated[str, typer.Option(help="SQL condition, e.g. \"host like '%sentry%'\"")] = "",
         all_columns: Annotated[bool, typer.Option("--all-columns")] = False,
         runs_root: RunsRoot = ROOT, app_: AppOpt = None, run: RunOpt = None, debug: Debug = False) -> None:
    """Inspect stored data (read-only) - the main debugging tool."""
    if table not in _SHOW_COLS:
        raise ClaimCheckError(f"unknown table '{table}'. Choose: {', '.join(_SHOW_COLS)}")
    with _ctx(runs_root, app_, run, 0, debug, write=False) as ctx:
        cols = "*" if all_columns else _SHOW_COLS[table]
        sql = f"SELECT {cols} FROM {table}" + (f" WHERE {where}" if where else "") + f" ORDER BY id DESC LIMIT {int(limit)}"  # noqa: S608  # table is allow-listed; --where runs on a read-only, single-statement connection  # nosec B608
        names, rows = ctx.store.query_readonly(sql, limit)
        ui.table(f"{table} (newest {len(rows)})", names, [[truncate(str(v), 90) for v in r] for r in rows])


@app.command()
def sql(query: Annotated[str, typer.Argument(help="A single SELECT statement")], runs_root: RunsRoot = ROOT, app_: AppOpt = None,
        run: RunOpt = None, debug: Debug = False) -> None:
    """Run a read-only SQL query on the run store (SELECT/WITH only)."""
    with _ctx(runs_root, app_, run, 0, debug, write=False) as ctx:
        names, rows = ctx.store.query_readonly(query)
        ui.table(f"{len(rows)} row(s)", names, [[truncate(str(v), 100) for v in r] for r in rows])


@app.command()
def verify(runs_root: RunsRoot = ROOT, app_: AppOpt = None, run: RunOpt = None, debug: Debug = False) -> None:
    """Check that raw capture files still match the SHA-256 recorded at ingest (detects corruption or tampering)."""
    with _ctx(runs_root, app_, run, 0, debug, write=False) as ctx:
        rows = verify_raw_files(ctx.store, ctx.run)
        if not rows:
            ui.info("no raw capture files in this run")
            return
        ui.table("raw files", ["file", "status", "sha256 (recorded)"], [[r["file"], r["status"], (r["expected"] or "")[:16]] for r in rows])
        bad = [r for r in rows if r["status"] in ("changed", "missing")]
        if bad:
            ui.error(f"{len(bad)} raw file(s) changed or missing since ingestion: the store no longer matches the evidence on disk")
            raise typer.Exit(1)
        ui.ok(f"{len(rows)} raw file(s) verified")


@app.command()
def events(limit: int = 40, level: Annotated[str | None, typer.Option(help="INFO|WARN|ERROR|STEP|OK")] = None,
           runs_root: RunsRoot = ROOT, app_: AppOpt = None, run: RunOpt = None, debug: Debug = False) -> None:
    """Show the persistent event journal (what happened, when)."""
    with _ctx(runs_root, app_, run, 0, debug, write=False) as ctx:
        ui.table("events", ["id", "ts", "level", "attempt", "message"], [[e["id"], e["ts"], e["level"], e["attempt_id"] or "", truncate(e["message"], 110)] for e in ctx.store.events(limit, level)])


@app.command("exclude")
def exclude_cmd(attempt_id: Annotated[int, typer.Argument()], runs_root: RunsRoot = ROOT, app_: AppOpt = None, run: RunOpt = None) -> None:
    """Exclude an attempt from analysis (e.g. a noisy capture). Data is kept; reversible with `include`."""
    with _ctx(runs_root, app_, run, 0, False) as ctx:
        if not ctx.store.set_excluded(attempt_id, True):
            raise ClaimCheckError(f"no attempt with id {attempt_id}")
        ctx.store.log("INFO", f"attempt {attempt_id} excluded by user")
        ui.ok(f"attempt {attempt_id} excluded. Re-run `claimcheck resume` to refresh downstream results.")


@app.command("include")
def include_cmd(attempt_id: Annotated[int, typer.Argument()], runs_root: RunsRoot = ROOT, app_: AppOpt = None, run: RunOpt = None) -> None:
    """Undo `exclude`."""
    with _ctx(runs_root, app_, run, 0, False) as ctx:
        if not ctx.store.set_excluded(attempt_id, False):
            raise ClaimCheckError(f"no attempt with id {attempt_id}")
        ctx.store.log("INFO", f"attempt {attempt_id} re-included by user")
        ui.ok(f"attempt {attempt_id} included again")


@app.command()
def export(out: Annotated[Path | None, typer.Option("--out", "-o")] = None, runs_root: RunsRoot = ROOT, app_: AppOpt = None, run: RunOpt = None) -> None:
    """Zip a whole run (to move it out of the VM). Read-only on the run; never overwrites the target."""
    rd: RunDir = resolve_run(runs_root, app_, run)
    target = out or unique_path(Path.cwd(), f"{rd.app_slug}_{rd.run_id}", ".zip")
    if target.exists():
        raise ClaimCheckError(f"{target} already exists (not overwritten)")
    n = 0
    with zipfile.ZipFile(target, "x", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(rd.path.rglob("*")):
            # symlinks are never followed (a hostile run could point at ~/.ssh) and the archive never contains itself
            if p.is_symlink() or p.resolve() == target.resolve():
                continue
            if p.is_file() and p.name != "run.lock" and not p.name.endswith(("-wal", "-shm")):
                z.write(p, Path(rd.app_slug) / rd.run_id / p.relative_to(rd.path))
                n += 1
        # a WAL-mode database may hold recent writes in -wal: snapshot it consistently
    _consistent_db_snapshot(rd, target)
    ui.ok(f"exported {n} files -> {target} ({human_bytes(target.stat().st_size)})")
    ui.warn("the archive contains raw captures, payload samples and logs: keep it private, do not publish it")


def _consistent_db_snapshot(rd: RunDir, target: Path) -> None:
    """Replace store.sqlite in the zip by a consistent snapshot (sqlite backup API), including WAL content."""
    import shutil
    import sqlite3
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        snap = Path(td) / "store.sqlite"
        src = sqlite3.connect(f"file:{rd.store_path.as_posix()}?mode=ro", uri=True)
        dst = sqlite3.connect(str(snap))
        try:
            src.backup(dst)
        finally:
            dst.close()
            src.close()
        tmp_zip = target.with_suffix(".tmp")
        arc = str(Path(rd.app_slug) / rd.run_id / "store.sqlite").replace("\\", "/")
        with zipfile.ZipFile(target) as zin, zipfile.ZipFile(tmp_zip, "x", zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                if item.filename.replace("\\", "/") != arc:
                    zout.writestr(item, zin.read(item.filename))
            zout.write(snap, arc)
        shutil.move(str(tmp_zip), str(target))


@app.command()
def benchmark(truth: Annotated[list[Path], typer.Argument(help="Truth YAML file(s), e.g. benchmark/truth/canary-clean.yaml")],
              runs_root: RunsRoot = ROOT, app_: AppOpt = None, run: RunOpt = None) -> None:
    """Compare verdicts/labels of a run with manually verified ground truth (precision / recall)."""
    all_ok = True
    for tf in truth:
        t = load_truth(tf)
        rd = resolve_run(runs_root, app_ or t["slug"], run or t.get("run"))
        with Store(rd.store_path, readonly=True) as st:
            verdicts, labels = observed_from_store(st)
        res = evaluate(t, verdicts, labels)
        ui.table(f"{tf.name}  (run {rd.run_id})", ["level", "item", "expected", "observed", "match"],
                 [[r["level"], r["item"], r["expected"], r["observed"], "OK" if r["match"] else "MISMATCH"] for r in res["rows"]])
        ui.info(f"verdict metrics: {res['verdict_metrics']}  |  host metrics: {res['host_metrics']}")
        all_ok &= res["all_match"]
    (ui.ok if all_ok else ui.warn)("all expectations met" if all_ok else "some expectations NOT met")
    if not all_ok:
        raise typer.Exit(1)


def _harden_streams() -> None:
    """A Windows console/redirect in cp1252 cannot print e.g. '\u2265' or Japanese: never crash AFTER the data was saved."""
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(Exception):
            stream.reconfigure(errors="replace")


def main() -> None:
    _harden_streams()
    try:
        app()
    except ClaimCheckError as e:
        if _STATE["debug"]:
            raise
        ui.error(str(e))
        if e.hint:
            ui.info("hint: " + e.hint)
        sys.exit(2)
    except KeyboardInterrupt:
        ui.warn("interrupted (data already written is kept; run `claimcheck status`)")
        sys.exit(130)
    except sqlite3.Error as e:
        if _STATE["debug"]:
            raise
        ui.error(f"database error: {e}")
        ui.info("'locked' = another claimcheck process is writing; 'malformed'/'not a database' = damaged file "
                "(restore from a `claimcheck export` zip; raw/*.jsonl can be re-ingested)")
        sys.exit(2)
    except BrokenPipeError:
        sys.exit(0)
    except Exception as e:  # noqa: BLE001
        if _STATE["debug"]:
            raise
        ui.error(f"unexpected {type(e).__name__}: {e}")
        ui.info("re-run with --debug for the traceback; details are also in the run's logs/claimcheck.log and `claimcheck events`")
        sys.exit(1)


if __name__ == "__main__":
    main()
