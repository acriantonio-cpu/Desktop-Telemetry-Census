"""Phase orchestration. Every phase = one *attempt* recorded in the store (append-only history)."""

from __future__ import annotations

import os
import shutil
import subprocess  # argv lists only, never shell=True; commands come from the user's own manifest  # nosec B404
import traceback
from collections import Counter
from collections.abc import Callable
from pathlib import Path

from claimcheck.claims import (
    GENERIC_DISCLOSURE, extract_claims, extract_disclosed_vendors, http_fetch, is_usable_policy, load_documents,
)
from claimcheck.classify.blocklists import load_blocklists
from claimcheck.classify.dnsutil import resolve_cname_chain
from claimcheck.classify.engine import classify_flows
from claimcheck.context import Context
from claimcheck.dynamic.ingest import ingest_all
from claimcheck.errors import ClaimCheckError, PreconditionError
from claimcheck.models import (
    CAPTURE_PHASES, DONE, FAILED, INTERRUPTED, OPTIONAL_PHASES, PARTIAL, PHASES, RUNNING, PhaseResult,
)
from claimcheck.report.render import write_report
from claimcheck.resources import resolve_command
from claimcheck.scoring.checks import build_facts, run_checks, summarize
from claimcheck.static.scanner import scan_install, scan_repo
from claimcheck.ui import ui
from claimcheck.util import truncate, unique_path

# phase -> phases whose output it consumes (used to detect stale results)
DEPENDS = {
    "classify": list(CAPTURE_PHASES),
    "score": ["claims", "static", "classify"],
    "report": ["score"],
}
AUTOMATIC = ["claims", "static", "classify", "score", "report"]
MANIFEST_SENSITIVE = {"classify"}  # results that depend on manifest content (first_party/allowed domains, thresholds)


def _log(ctx: Context) -> Callable[[str, str], None]:
    def log(level: str, message: str) -> None:
        {"WARN": ui.warn, "ERROR": ui.error, "DEBUG": ui.debug}.get(level, ui.verbose)(message)
    return log


def run_phase(ctx: Context, phase: str, fn: Callable[[int], PhaseResult], params: dict | None = None) -> PhaseResult:
    """Wrap a phase function in an attempt record; status/summary/note are always persisted."""
    full = {**(params or {}), "manifest_sha256": ctx.manifest_sha256}
    if phase in DEPENDS:  # the exact attempt ids consumed: `exclude`/`include` change them without creating a newer id
        full["inputs"] = {d: ctx.store.effective_attempt_ids(d) for d in DEPENDS[phase]}
    attempt_id = ctx.store.begin_attempt(phase, full)
    ctx.current_attempt = attempt_id
    seq = ctx.store.get_attempt(attempt_id)["seq"]
    ui.step(f"{phase} (attempt #{seq})")
    try:
        result = fn(attempt_id)
    except KeyboardInterrupt:
        ctx.store.finish_attempt(attempt_id, INTERRUPTED, note="interrupted by user (Ctrl+C)")
        ui.warn(f"{phase} interrupted; partial data (if any) is kept. Re-run the command to continue.")
        raise
    except ClaimCheckError as e:
        ctx.store.finish_attempt(attempt_id, FAILED, note=str(e)[:500])
        raise
    except Exception as e:
        ctx.store.finish_attempt(attempt_id, FAILED, note=f"{type(e).__name__}: {e}"[:500])
        ctx.store.log("ERROR", traceback.format_exc()[-3500:], attempt_id)
        raise
    finally:
        ctx.current_attempt = None
    ctx.store.finish_attempt(attempt_id, result.status, result.summary, result.note)
    return result


# ------------------------------------------------------------------ recovery
def recover_orphans(ctx: Context) -> int:
    """Ingest raw capture files never fully ingested (e.g. crash mid-capture). Idempotent."""
    pending = ctx.store.raw_files(only_incomplete=True)
    if not pending:
        return 0
    ui.warn(f"{len(pending)} raw capture file(s) not fully ingested (previous run interrupted?): recovering ...")
    stats = ingest_all(ctx.store, ctx.run, final=True, log=_log(ctx))
    n = sum(s["inserted"] for s in stats)
    ui.ok(f"recovered {n} new record(s) from raw files")
    for raw in pending:
        att = ctx.store.get_attempt(raw["attempt_id"])
        if att and att["status"] == INTERRUPTED and att["phase"] in CAPTURE_PHASES:
            # data exists => make the interrupted capture usable (still visible as partial, still excludable)
            row = ctx.store._one("SELECT COUNT(*) AS n FROM flows WHERE attempt_id=?", (att["id"],))
            if row and row["n"] > 0:
                with ctx.store._lock, ctx.store.conn:
                    ctx.store.conn.execute("UPDATE attempts SET status=?, note=COALESCE(note,'')||' [promoted to partial after recovery]' WHERE id=?", (PARTIAL, att["id"]))
    return n


# ------------------------------------------------------------------ claims
def phase_claims(ctx: Context, attempt_id: int, fetch: Callable | None = None) -> PhaseResult:
    docs_dir = ctx.run.artifacts_dir / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)
    docs = load_documents(ctx.manifest, docs_dir, _log(ctx), fetch or http_fetch)
    loaded = [d for d in docs if d.text]
    failed = [d for d in docs if d.error]
    if docs and not loaded:
        raise PreconditionError("no document could be loaded: " + "; ".join(f"{d.ref}: {d.error}" for d in failed[:3]),
                                hint="Check URLs/paths in sources.documents and your internet connection.")
    if not docs:
        ui.warn("no documents configured (sources.documents / repo README): no claims can be extracted")
    claims = extract_claims(loaded)
    for c in claims:
        c["attempt_id"] = attempt_id
    ctx.store.insert_many("claims", claims)
    usable = [d for d in loaded if d.role != "privacy_policy" or is_usable_policy(d)]
    policies_ok = [d for d in loaded if d.role == "privacy_policy" and is_usable_policy(d)]
    policies_bad = [d for d in loaded if d.role == "privacy_policy" and not is_usable_policy(d)]
    disclosed = extract_disclosed_vendors(usable, ctx.sigs)
    for x in disclosed:
        x["attempt_id"] = attempt_id
    ctx.store.insert_many("disclosed", disclosed)
    by_kind = Counter(c["kind"] for c in claims)
    for c in claims:
        ui.verbose(f"claim [{c['kind']}] ({c['confidence']}) {truncate(c['text'], 110)}")
    ui.table("claims extracted", ["kind", "count", "example"], [[k, n, truncate(next(c['text'] for c in claims if c['kind'] == k), 80)] for k, n in by_kind.items()])
    named = sorted(x["sdk_id"] for x in disclosed if x["sdk_id"] != GENERIC_DISCLOSURE)
    if named:
        ui.info("vendors named in the privacy policy: " + ", ".join(named))
    if any(x["sdk_id"] == GENERIC_DISCLOSURE for x in disclosed):
        ui.info("the privacy policy admits telemetry/analytics in general terms")
    if failed:
        ui.warn(f"{len(failed)} document(s) could not be loaded (see log)")
    if policies_bad:
        ui.warn(f"{len(policies_bad)} privacy policy document(s) look empty / bot-check / JS shell: NOT used for disclosure checks")
    if not claims and loaded:
        ui.warn("documents were loaded but no claim was extracted: check that they contain the real text (JavaScript-rendered pages are not supported)")
    doc_warnings = [f"{d.role} {truncate(d.ref, 60)}: {w}" for d in loaded for w in d.warnings][:10]
    return PhaseResult(DONE, {
        "docs_total": len(docs), "docs_loaded": len(loaded), "docs_failed": len(failed),
        "policy_docs_loaded": len(policies_ok), "policy_docs_unusable": len(policies_bad), "doc_warnings": doc_warnings,
        "claims_by_kind": dict(by_kind), "disclosed_vendors": len([x for x in disclosed if x["sdk_id"] != GENERIC_DISCLOSURE])},
        note=f"{len(failed)} document(s) failed" if failed else "")


# ------------------------------------------------------------------ static
def _git_env() -> dict:
    """Never wait for a human: a wrong/private URL must fail fast, not hang 15 minutes on a credential prompt."""
    env = os.environ.copy()
    env.update({"GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never", "GIT_ASKPASS": ""})
    return env


def _git(git: list[str], repo: Path, *args: str) -> str:
    try:
        r = subprocess.run([*git, "-C", str(repo), *args], capture_output=True, text=True, timeout=30, env=_git_env(), stdin=subprocess.DEVNULL)  # noqa: S603  # nosec B603
    except (subprocess.SubprocessError, OSError):
        return ""
    return r.stdout.strip() if r.returncode == 0 else ""


def repo_info(repo: Path, version: str) -> dict:
    """Which commit was scanned, and does it look like the installed version? (a wrong tag fakes 'SDK only in binary')."""
    info: dict = {"path": str(repo), "commit": "", "describe": "", "tags": [], "version_match": None}
    git = resolve_command("git")
    if not git or not (Path(repo) / ".git").exists():
        return info
    info["commit"] = _git(git, repo, "rev-parse", "HEAD")
    info["describe"] = _git(git, repo, "describe", "--tags", "--always")
    info["tags"] = _git(git, repo, "tag", "--points-at", "HEAD").split()[:10]
    v = (version or "").strip().lstrip("vV")
    if v and (info["commit"] or info["describe"]):
        info["version_match"] = any(v in str(h) for h in [info["describe"], *info["tags"]])
    return info


def ensure_repo(ctx: Context) -> Path | None:
    src = ctx.manifest.sources
    if src.repo_path and Path(src.repo_path).is_dir():
        return Path(src.repo_path)
    if src.repo_path:
        ui.warn(f"sources.repo_path does not exist: {src.repo_path}")
    if not src.repo_url:
        return None
    dest = ctx.run.artifacts_dir / "repo"
    if dest.is_dir() and any(dest.iterdir()):
        if (dest / ".git").exists():
            ui.info(f"reusing previously cloned repo: {dest}")
            return dest
        aside = unique_path(dest.parent, "repo.incomplete", "")
        dest.rename(aside)  # an interrupted clone must never be mistaken for the real source
        ui.warn(f"found an incomplete clone: moved to {aside.name}; cloning again")
    git = resolve_command("git")
    if not git:
        ui.warn("git not found: cannot clone sources.repo_url. Clone it manually and set sources.repo_path.")
        return None
    partial = dest.with_name(f"repo.partial-{os.getpid()}")
    shutil.rmtree(partial, ignore_errors=True)
    # "--" ends option parsing: a hostile URL/ref can never be interpreted as a git option (manifest validation also rejects it)
    cmd = [*git, "-c", "protocol.ext.allow=never", "-c", "protocol.file.allow=never", "clone", "--depth", "1"] \
        + (["--branch", src.repo_ref] if src.repo_ref else []) + ["--", src.repo_url, str(partial)]
    ui.info("cloning repo: " + " ".join(cmd))
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=900, env=_git_env(), stdin=subprocess.DEVNULL)  # noqa: S603  # argv list, no shell, validated input  # nosec B603
        partial.replace(dest)  # atomic: `repo/` exists only if the clone completed
    except (subprocess.SubprocessError, OSError) as e:
        detail = getattr(e, "stderr", "") or str(e)
        ui.warn(f"git clone failed: {truncate(str(detail), 300)}")
        shutil.rmtree(partial, ignore_errors=True)
        return None
    return dest


def phase_static(ctx: Context, attempt_id: int, sides: set[str] | None = None) -> PhaseResult:
    sides = sides or {"binary", "repo"}
    cfg = ctx.manifest.static
    app = ctx.manifest.app
    evidence: list[dict] = []
    coverage: dict = {}
    scanned: list[str] = []
    rinfo: dict = {}

    def progress_factory(label: str):
        def progress(done: int, total: int, rel: str) -> None:
            if done % 200 == 0 or done == total:
                ui.verbose(f"[{label}] {done}/{total} files ... {truncate(rel, 70)}")
        return progress

    if "binary" in sides:
        if app.install_dir and Path(app.install_dir).exists():
            ui.info(f"scanning installed app: {app.install_dir} (workers={cfg.workers}, max_file={cfg.max_file_mb} MB, budget={cfg.max_total_mb} MB)")
            r = scan_install(Path(app.install_dir), ctx.sigs, cfg, progress_factory("binary"), lambda m: ui.verbose(m))
            evidence += r.evidence
            coverage["binary"] = r.coverage
            scanned.append("binary")
        else:
            ui.warn("app.install_dir is empty or missing: binary side skipped" + (f" ({app.install_dir})" if app.install_dir else ""))
    if "repo" in sides:
        repo = ensure_repo(ctx)
        if repo:
            ui.info(f"scanning source repo: {repo}")
            r = scan_repo(repo, ctx.sigs, cfg, progress_factory("repo"), lambda m: ui.verbose(m))
            evidence += r.evidence
            coverage["repo"] = r.coverage
            scanned.append("repo")
            rinfo = repo_info(repo, app.version)
            ui.info(f"repo commit {rinfo['commit'][:12] or '?'} ({rinfo['describe'] or 'no tag info'})")
            if rinfo["version_match"] is False:
                ui.warn(f"the repo does not look like app.version={app.version!r}: check out the tag of the INSTALLED release, "
                        "otherwise the binary-vs-source comparison is unreliable")
        else:
            ui.warn("no source repo available: repo side skipped (set sources.repo_path or sources.repo_url)")
    if not scanned:
        raise PreconditionError("nothing to scan", hint="Set app.install_dir and/or sources.repo_path/repo_url in the run manifest.")
    for e in evidence:
        e["attempt_id"] = attempt_id
    ctx.store.insert_many("static_evidence", evidence)
    by = Counter((e["side"], e["sdk_id"]) for e in evidence)
    ui.table("telemetry SDK evidence", ["side", "sdk", "items", "strongest kind"],
             [[s, k, n, max((e for e in evidence if e["side"] == s and e["sdk_id"] == k), key=lambda e: e["confidence"])["kind"]] for (s, k), n in sorted(by.items())])
    for side, cov in coverage.items():
        ui.info(f"[{side}] scanned {cov['files_scanned']}/{cov['files_seen']} files, {cov['bytes_scanned'] / 1048576:.0f} MB in {cov['seconds']}s; "
                f"skipped: glob={cov['skipped_glob']} runtime={cov['skipped_runtime']} size={cov['skipped_size']} budget={cov['skipped_budget']}")
        if cov["skipped_budget"] or cov["skipped_size"]:
            ui.warn(f"[{side}] some files were not scanned because of limits: raise static.max_file_mb / max_total_mb if you have the resources")
        for err in cov["errors"][:5]:
            ui.warn(f"[{side}] {err}")
    if coverage.get("binary", {}).get("opaque_container_count"):
        ui.warn(f"{coverage['binary']['opaque_container_count']} compressed container(s)/installer(s) cannot be inspected: "
                "scan the INSTALLED application folder instead")
    return PhaseResult(DONE, {"sides": scanned, "coverage": coverage, "evidence": len(evidence), "repo_info": rinfo})


# ------------------------------------------------------------------ classify
def phase_classify(ctx: Context, attempt_id: int, resolver: Callable | None = None) -> PhaseResult:
    ids: list[int] = []
    for ph in CAPTURE_PHASES:
        ids += ctx.store.effective_attempt_ids(ph)
    flows = ctx.store.flows_for_classification(ids)
    if not flows:
        ui.warn("no captured flows: nothing to classify (run `claimcheck capture` or `import-flows`)")
        return PhaseResult(DONE, {"flows": 0, "hosts": 0}, note="no flows")
    cfg = ctx.manifest.classify
    bl = load_blocklists(cfg.blocklists, include_default_dir=True, log=lambda m: ui.verbose(m))
    ui.info(f"classifying {len(flows)} records; blocklist domains: {len(bl)}; CNAME resolution: {'on' if cfg.resolve_cname else 'off'}")
    if cfg.resolve_cname and resolver is None:
        def resolver(h, _t=cfg.dns_timeout):  # type: ignore[misc]
            return resolve_cname_chain(h, timeout=_t)
    notes: dict = {}
    labels, dns_rows = classify_flows(flows, ctx.manifest, ctx.sigs, bl, resolver if cfg.resolve_cname else None, _log(ctx), notes)
    for row in labels + dns_rows:
        row["attempt_id"] = attempt_id
    ctx.store.insert_many("labels", labels)
    ctx.store.insert_many("dns_records", dns_rows)
    counts = Counter(x["label"] for x in labels)
    ui.table("traffic classification", ["phase", "host", "label", "score", "flows"],
             [[x["capture_phase"].replace("capture_", ""), x["host"], x["label"], f"{x['score']:.2f}", x["n_flows"]] for x in labels][:60])
    if len(labels) > 60:
        ui.info(f"... {len(labels) - 60} more rows (use `claimcheck show labels`)")
    return PhaseResult(DONE, {"flows": len(flows), "hosts": len(labels), "labels": dict(counts), "dns_lookups": len(dns_rows), "blocklist_domains": len(bl),
                                 "blocklists": bl.provenance, "dns_skipped": len(notes.get("dns_skipped_hosts", [])),
                                 "dns_unavailable": bool(notes.get("dns_unavailable"))})


# ------------------------------------------------------------------ score
def phase_score(ctx: Context, attempt_id: int) -> PhaseResult:
    stale = [ph for ph in ("classify",) if is_stale(ctx, ph)]
    if stale:
        ui.warn("classify results are older than the captured data (exclude/include, new capture or edited manifest): re-run `claimcheck classify`")
    facts = build_facts(ctx.store, stale)
    for w in facts.quality:
        ui.warn("data quality: " + w)
    verdicts = run_checks(facts)
    for v in verdicts:
        v["attempt_id"] = attempt_id
    ctx.store.insert_many("verdicts", verdicts)
    ui.table("verdicts", ["verdict", "sev", "check", "title"], [[v["verdict"], v["severity"], v["check_id"], truncate(v["title"], 70)] for v in verdicts])
    for v in verdicts:
        ui.verbose(f"{v['check_id']}: {v['explanation']}")
    return PhaseResult(DONE, {"counts": summarize(verdicts), "checks": len(verdicts)})


# ------------------------------------------------------------------ report
def phase_report(ctx: Context, attempt_id: int) -> PhaseResult:
    seq = ctx.store.get_attempt(attempt_id)["seq"]
    html_path, json_path = write_report(ctx, seq)
    ui.ok(f"report written: {html_path}")
    ui.info(f"machine-readable: {json_path}")
    return PhaseResult(DONE, {"html": html_path, "json": json_path})


# ------------------------------------------------------------------ status / resume
def is_stale(ctx: Context, phase: str) -> bool:
    deps = DEPENDS.get(phase)
    if not deps:
        return False
    mine = ctx.store.effective_attempt_ids(phase)
    if not mine:
        return False
    newest_dep = max((max(ctx.store.effective_attempt_ids(d), default=0) for d in deps), default=0)
    if newest_dep > max(mine):
        return True
    params = (ctx.store.get_attempt(mine[-1]) or {}).get("params") or {}
    inputs = params.get("inputs")
    if isinstance(inputs, dict):  # set comparison: excluding/including an attempt changes the set, not the newest id
        for d in deps:
            if sorted(inputs.get(d, [])) != sorted(ctx.store.effective_attempt_ids(d)):
                return True
    if phase in MANIFEST_SENSITIVE and params.get("manifest_sha256") and params["manifest_sha256"] != ctx.manifest_sha256:
        return True
    # transitive: if an upstream phase is itself stale, everything downstream of it is stale too
    return any(is_stale(ctx, d) for d in deps if d in DEPENDS)


def status_rows(ctx: Context) -> list[dict]:
    rows = []
    for ph in PHASES:
        s = ctx.store.phase_status(ph)
        last = s["last"]
        rows.append({
            "phase": ph, "status": s["status"] + (" (STALE: inputs are newer)" if is_stale(ctx, ph) else ""),
            "attempts": s["attempts"], "effective": ",".join(str(i) for i in s["effective"]) or "-",
            "last_started": last["started_at"] if last else "", "note": (last or {}).get("note") or "",
            "optional": ph in OPTIONAL_PHASES,
        })
    return rows


def next_actions(ctx: Context) -> list[str]:
    tips = []
    st = {p: ctx.store.phase_status(p) for p in PHASES}
    if not st["claims"]["effective"]:
        tips.append("claimcheck claims                      # extract the privacy claims")
    if not st["static"]["effective"]:
        tips.append("claimcheck static                      # scan installed app + repo for SDKs")
    for ph in CAPTURE_PHASES:
        if not st[ph]["effective"] and ph not in OPTIONAL_PHASES:
            tips.append(f"claimcheck capture --phase {ph.replace('capture_', '')}          # observe network traffic")
    if not st["capture_optout"]["effective"]:
        tips.append("claimcheck capture --phase optout       # (optional) does telemetry stop after opt-out?")
    for ph in ("classify", "score", "report"):
        if not st[ph]["effective"] or is_stale(ctx, ph):
            tips.append(f"claimcheck {ph}")
    return tips


def resume(ctx: Context, with_capture: bool = False) -> list[str]:
    """Run every automatic phase that is missing, failed or stale. Capture phases only when asked."""
    ran: list[str] = []
    if with_capture:
        from claimcheck.dynamic.capture import run_capture

        for ph in CAPTURE_PHASES:
            if ph in OPTIONAL_PHASES or ctx.store.effective_attempt_ids(ph):
                continue
            run_phase(ctx, ph, lambda a, ph=ph: run_capture(ctx, a, ph), {"resume": True})
            ran.append(ph)
    fns = {"claims": phase_claims, "static": phase_static, "classify": phase_classify, "score": phase_score, "report": phase_report}
    for ph in AUTOMATIC:
        if not ctx.store.effective_attempt_ids(ph) or is_stale(ctx, ph):
            if ph == "classify" and not any(ctx.store.effective_attempt_ids(c) for c in CAPTURE_PHASES):
                ui.warn("classify skipped: no capture data yet (run `claimcheck capture --phase idle`)")
                continue
            try:
                run_phase(ctx, ph, lambda a, ph=ph: fns[ph](ctx, a), {"resume": True})
                ran.append(ph)
            except ClaimCheckError as e:
                ui.warn(f"{ph} could not run: {e}" + (f" | hint: {e.hint}" if e.hint else ""))
    return ran


__all__ = ["run_phase", "resume", "status_rows", "next_actions", "RUNNING"]
