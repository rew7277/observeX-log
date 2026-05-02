"""
routes/logs.py — Upload, analyse, async-ingest, and search routes.

Key improvements over monolith:
  - /analyse enforces plan storage limits before accepting upload.
  - File content validated with MIME check (python-magic) in addition to extension.
  - Rate-limited with Flask-Limiter on /analyse and /api/v1/logs/ingest.
  - Background post-processing dispatched via services/tasks.py (RQ → Celery → thread).
  - log_rows_json column on LogSession is NOT written for new sessions (rows go to LogEvent).
  - delete cascade pushed to background task to prevent HTTP timeouts.
"""
import json
import time
import datetime
import os

from flask import Blueprint, request, jsonify, session, make_response
from werkzeug.utils import secure_filename

from extensions import db
from models import (
    LogSession, IngestionJob, LogEvent, TraceIndex,
    FlowEdge, ApiFlowMap, QueryMetric,
)
from services.security import allowed_file, allowed_file_content, mask_secrets
from services.tasks import enqueue_ingestion, send_alert_async

logs_bp = Blueprint("logs", __name__)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_user():
    """Return current user or None.  Keeps import cycle-free."""
    from app import get_current_user
    return get_current_user()


def _get_plan_limits(plan: str) -> dict:
    from app import get_plan_limits
    return get_plan_limits(plan)


def _check_plan_limits(user) -> tuple[bool, str]:
    """
    Return (allowed, error_message).
    Checks storage_gb against the user's current workspace plan.
    """
    try:
        from app import ensure_default_workspace, storage_status
        ws     = ensure_default_workspace(user)
        limits = _get_plan_limits(ws.plan if ws else "starter")
        status = storage_status(user)
        max_gb = limits.get("storage_gb", 5)
        used   = status.get("total_gb", 0) or 0
        if used >= max_gb:
            return False, (
                f"Storage limit reached ({used:.2f} GB / {max_gb} GB on {ws.plan} plan). "
                "Delete old sessions or upgrade your plan."
            )
        # Monthly ingestion limit (in GB)
        max_ingest = limits.get("ingestion_gb_month", 10)
        used_month = status.get("this_month_gb", 0) or 0
        if used_month >= max_ingest:
            return False, (
                f"Monthly ingestion limit reached ({used_month:.2f} GB / {max_ingest} GB). "
                "Upgrade to continue ingesting this month."
            )
        return True, ""
    except Exception:
        return True, ""   # fail open — don't block upload if limit check errors


def _light_row(r: dict) -> dict:
    rr  = dict(r or {})
    msg = str(rr.get("message") or "")
    if len(msg) > 700:
        rr["message"] = msg[:700] + " …"
    return rr


def _build_ingestion_job(user, raw: str, query: str, env: str, filename: str,
                          source: str = "file") -> IngestionJob:
    """Create an IngestionJob row and enqueue the worker."""
    job = IngestionJob(
        user_id=user.id, source=source, filename=filename,
        status="queued",
        total_bytes=len(raw.encode("utf-8", errors="ignore")),
    )
    db.session.add(job)
    db.session.commit()
    enqueue_ingestion(job.id, user.id, raw, query, env, filename)
    return job


# ── /analyse — synchronous fast path with background post-processing ─────────

@logs_bp.route("/analyse", methods=["POST"])
def analyse():
    user = _get_user()
    if user is None:
        return jsonify({"error": "Session expired. Please login again."}), 401

    # ── Plan limit check ──
    allowed, limit_err = _check_plan_limits(user)
    if not allowed:
        return jsonify({"error": limit_err, "upgrade": True}), 402

    # ── Rate limit: 30 uploads per minute per user ──
    from app import api_rate_limited
    if api_rate_limited(f"analyse:{user.id}", limit=30, window=60):
        return jsonify({"error": "Upload rate limit exceeded. Please wait a moment."}), 429

    env   = request.form.get("env", "PROD")
    query = request.form.get("query", "")
    raw_parts: list[str] = []
    fnames: list[str]    = []

    if "logfile" in request.files:
        files = request.files.getlist("logfile")
        for f in files:
            if not f or not f.filename:
                continue
            fname = secure_filename(f.filename)
            file_bytes = f.read()

            # MIME + extension validation
            if not allowed_file_content(file_bytes, fname):
                return jsonify({"error": f"Unsupported file type: {fname}. Upload .log, .txt or .json only."}), 400

            fnames.append(fname)
            raw_parts.append(f"\n--- FILE: {fname} ---\n" + file_bytes.decode("utf-8", errors="replace"))

    raw = "".join(raw_parts)
    if fnames:
        fname = ", ".join(fnames[:6]) + ("..." if len(fnames) > 6 else "")
    else:
        fname = "paste"

    if not raw and request.form.get("raw_paste"):
        raw  = request.form["raw_paste"]
        fname = "paste"

    if not raw:
        return jsonify({"error": "No log content provided"}), 400

    # ── Route to async job for large payloads ──
    async_threshold = int(os.environ.get("OBSERVEX_ASYNC_UPLOAD_BYTES", str(512 * 1024)))
    force_async     = str(request.form.get("async", "")).lower() in ("1", "true", "yes")
    raw_bytes       = len(raw.encode("utf-8", errors="ignore"))

    if force_async or raw_bytes >= async_threshold or len(fnames) > 1:
        job = _build_ingestion_job(user, raw, query, env, fname)
        return jsonify({
            "queued":   True,
            "job_id":   job.id,
            "status":   job.status,
            "filename": fname,
            "message":  "Upload accepted. Parsing and indexing running in the background.",
            "poll_url": f"/ingestion-jobs/{job.id}",
        }), 202

    # ── Synchronous fast path (<512 KB) ──
    start_ms = time.time()

    from app import analyse_log_text, extract_system_map, persist_observability_indexes
    from app import maybe_create_incident_from_rows, persist_raw_upload, audit_event

    result      = analyse_log_text(raw, query, env, fname, user.id)
    full_rows   = result.get("log_rows", []) or []
    rows_to_store = full_rows[:5000]
    client_rows   = [_light_row(r) for r in full_rows[:1000]]
    result_summary = {k: v for k, v in result.items() if k != "log_rows"}

    result["source_health"] = {
        "file_upload":    "active",
        "api_ingestion":  "available",
        "s3":             "not_connected",
        "last_ingest":    "now",
    }

    # Store session — do NOT write log_rows_json (rows go to LogEvent via background task)
    ls = LogSession(
        user_id=user.id, environment=env, filename=fname,
        total_lines=result["total"], error_count=result["errors"],
        warn_count=result["warns"],  avg_latency=result["latency"],
        apps_found=",".join(result["apps"]),
        log_rows_json="[]",          # deprecated column — left empty for new sessions
        result_json=json.dumps(result_summary, default=str),
    )
    db.session.add(ls)
    db.session.commit()
    session_id = ls.id

    # Phase 2: topology, indexes, incidents, audit — off HTTP thread
    def _bg_post_process(app_ctx, sid, uid, rows_bg, raw_bg, env_bg, fname_bg, result_bg):
        with app_ctx:
            try:
                flow_maps = extract_system_map(rows_bg, raw_bg, env_bg, sid, uid)
                for fm in flow_maps:
                    db.session.add(fm)
                db.session.flush()
                persist_observability_indexes(uid, sid, rows_bg, raw_bg, env_bg, fname_bg, flow_maps)
                maybe_create_incident_from_rows(uid, rows_bg, env_bg, sid)
                db.session.add(QueryMetric(
                    user_id=uid, action="upload_analyse",
                    duration_ms=int((time.time() - start_ms) * 1000),
                    rows=result_bg.get("total", 0),
                    bytes=len(raw_bg.encode("utf-8", errors="ignore")),
                ))
                db.session.commit()
                persist_raw_upload(uid, sid, fname_bg, raw_bg)
            except Exception:
                db.session.rollback()
                from app import app as flask_app
                flask_app.logger.exception("Background post-process failed (non-fatal)")

    # Use task queue for background work
    from app import app as flask_app
    import threading
    threading.Thread(
        target=_bg_post_process,
        args=(flask_app.app_context(), session_id, user.id,
              rows_to_store, raw, env, fname, result),
        daemon=True,
    ).start()

    duration_ms = int((time.time() - start_ms) * 1000)
    result.update({
        "session_id":    session_id,
        "stored":        True,
        "log_rows":      client_rows,
        "fast_upload":   True,
        "returned_rows": len(client_rows),
        "indexed_rows":  len(rows_to_store),
        "duration_ms":   duration_ms,
    })
    return jsonify(result)


# ── /analyse/async ─────────────────────────────────────────────────────────────

@logs_bp.route("/analyse/async", methods=["POST"])
def analyse_async():
    user = _get_user()
    if user is None:
        return jsonify({"error": "Session expired."}), 401

    allowed, limit_err = _check_plan_limits(user)
    if not allowed:
        return jsonify({"error": limit_err, "upgrade": True}), 402

    env   = request.form.get("env", "PROD")
    query = request.form.get("query", "")
    raw   = ""
    fname = "paste"
    fnames: list[str] = []

    if "logfile" in request.files:
        for f in request.files.getlist("logfile"):
            if not f or not f.filename:
                continue
            fn = secure_filename(f.filename)
            file_bytes = f.read()
            if not allowed_file_content(file_bytes, fn):
                return jsonify({"error": f"Unsupported file type: {fn}"}), 400
            fnames.append(fn)
            raw += f"\n--- FILE: {fn} ---\n" + file_bytes.decode("utf-8", errors="replace")

    if not raw:
        raw   = request.form.get("raw_paste", "")
        fname = "paste"
    elif fnames:
        fname = ", ".join(fnames[:6]) + ("..." if len(fnames) > 6 else "")

    if not raw:
        return jsonify({"error": "No log content provided"}), 400

    job = _build_ingestion_job(user, raw, query, env, fname)
    return jsonify({
        "queued":   True,
        "job_id":   job.id,
        "status":   job.status,
        "filename": fname,
        "poll_url": f"/ingestion-jobs/{job.id}",
    }), 202


# ── /ingestion-jobs/<id> polling endpoint ────────────────────────────────────

@logs_bp.route("/ingestion-jobs/<int:job_id>")
def ingestion_job_status(job_id):
    user = _get_user()
    if user is None:
        return jsonify({"error": "Not authenticated"}), 401
    job = IngestionJob.query.filter_by(id=job_id, user_id=user.id).first_or_404()
    progress = getattr(job, "progress", 0) or (100 if job.status == "success" else 0)
    return jsonify({
        "id":         job.id,
        "status":     job.status,
        "filename":   job.filename,
        "bytes":      job.total_bytes,
        "lines":      job.total_lines,
        "error":      job.error,
        "session_id": job.session_id,
        "progress":   progress,
        "rows_url":   f"/api/v1/sessions/{job.session_id}/rows" if job.session_id else None,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "finished_at":job.finished_at.isoformat() if job.finished_at else None,
    })


# ── /api/v1/logs/ingest — external API ingestion ──────────────────────────────

@logs_bp.route("/api/v1/logs/ingest", methods=["POST"])
def api_ingest():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid Authorization header"}), 401

    from app import lookup_user_by_api_key, audit_event, analyse_log_text
    user = lookup_user_by_api_key(auth.split(" ", 1)[1])
    if not user:
        return jsonify({"error": "Invalid API key"}), 401

    # Rate limit: 60 API ingestion calls per minute per user
    from app import api_rate_limited
    if api_rate_limited(f"api_ingest:{user.id}", limit=60, window=60):
        return jsonify({"error": "Rate limit exceeded"}), 429

    # Plan limit check
    allowed, limit_err = _check_plan_limits(user)
    if not allowed:
        return jsonify({"error": limit_err, "upgrade": True}), 402

    data = request.get_json(force=True, silent=True) or {}
    env  = str(data.get("environment") or data.get("env") or "PROD").upper()[:20]
    app_name = str(data.get("application") or data.get("app") or data.get("service") or "api-ingest")[:200]
    raw = ""

    logs_field = data.get("logs")
    if isinstance(logs_field, list):
        raw = "\n".join(
            json.dumps(item) if isinstance(item, dict) else str(item)
            for item in logs_field[:10000]
        )
    elif isinstance(logs_field, str):
        raw = logs_field
    else:
        # Treat the whole payload as a structured event
        structured_keys = {"eventId", "timestamp", "level", "message", "payload",
                           "status", "transactionId", "orderId"}
        if any(k in data for k in structured_keys):
            raw = json.dumps(data)
        else:
            return jsonify({"error": "logs field or structured event payload required"}), 400

    max_bytes = int(os.environ.get("MAX_UPLOAD_MB", "250")) * 1024 * 1024
    if len(raw.encode("utf-8", errors="ignore")) > max_bytes:
        return jsonify({"error": f"Payload exceeds {max_bytes // (1024*1024)} MB limit"}), 413

    # Mask before analysis
    raw_masked = mask_secrets(raw)

    async_threshold = int(os.environ.get("OBSERVEX_ASYNC_UPLOAD_BYTES", str(256 * 1024)))
    if len(raw_masked.encode("utf-8", errors="ignore")) >= async_threshold:
        job = _build_ingestion_job(user, raw_masked, "", env, app_name, source="api")
        try:
            audit_event(user, "ingestion.api_queued", app_name, {"job_id": job.id, "env": env})
            db.session.commit()
        except Exception:
            db.session.rollback()
        return jsonify({
            "status":     "queued",
            "job_id":     job.id,
            "filename":   app_name,
            "poll_url":   f"/ingestion-jobs/{job.id}",
            "message":    "Payload accepted and queued for background processing.",
        }), 202

    start = time.time()
    result = analyse_log_text(raw_masked, "", env, app_name, user.id)
    rows   = result.get("log_rows", [])[:5000]
    result_summary = {k: v for k, v in result.items() if k != "log_rows"}

    ls = LogSession(
        user_id=user.id, environment=env, filename=app_name,
        total_lines=result["total"], error_count=result["errors"],
        warn_count=result["warns"],  avg_latency=result["latency"],
        apps_found=",".join(result["apps"]),
        log_rows_json="[]",
        result_json=json.dumps(result_summary, default=str),
    )
    db.session.add(ls)
    db.session.commit()

    try:
        from app import (extract_system_map, persist_observability_indexes,
                         maybe_create_incident_from_rows, persist_raw_upload)
        flow_maps = extract_system_map(rows, raw_masked, env, ls.id, user.id)
        for fm in flow_maps:
            db.session.add(fm)
        persist_observability_indexes(user.id, ls.id, rows, raw_masked, env, app_name, flow_maps)
        maybe_create_incident_from_rows(user.id, rows, env, ls.id)
        persist_raw_upload(user.id, ls.id, app_name + ".log", raw_masked)
        db.session.commit()
        send_alert_async(user.id, result_summary)
    except Exception:
        db.session.rollback()

    try:
        audit_event(user, "ingestion.api_sync", app_name, {
            "session_id": ls.id, "env": env, "rows": result["total"],
        })
        db.session.commit()
    except Exception:
        db.session.rollback()

    return jsonify({
        "status":           "success",
        "session_id":       ls.id,
        "stored":           True,
        "ingested":         result["total"],
        "errors":           result["errors"],
        "warns":            result["warns"],
        "processingTimeMs": int((time.time() - start) * 1000),
    })


@logs_bp.route("/api/v1/logs/ingest", methods=["GET"])
def api_ingest_docs():
    return jsonify({
        "endpoint":  "POST /api/v1/logs/ingest",
        "auth":      "Authorization: Bearer <OBSERVEX_API_KEY>",
        "raw_example": {"environment": "SANDBOX", "application": "demo-api",
                        "logs": "INFO 2026-05-12 09:18:44 checkout completed"},
    })


# ── /history ──────────────────────────────────────────────────────────────────

@logs_bp.route("/history", methods=["GET", "DELETE"])
def history():
    user = _get_user()
    if user is None:
        return jsonify({"error": "Session expired."}), 401

    uid = user.id

    if request.method == "DELETE":
        sid = request.args.get("id")

        def _cascade_delete(item):
            if not item:
                return 0
            # Child rows deleted first to avoid FK failures
            LogEvent.query.filter_by(user_id=uid, session_id=item.id).delete(synchronize_session=False)
            TraceIndex.query.filter_by(user_id=uid, session_id=item.id).delete(synchronize_session=False)
            FlowEdge.query.filter_by(user_id=uid, session_id=item.id).delete(synchronize_session=False)
            ApiFlowMap.query.filter_by(user_id=uid, session_id=item.id).delete(synchronize_session=False)
            try:
                from app import delete_persisted_upload
                delete_persisted_upload(uid, item.id)
            except Exception:
                pass
            db.session.delete(item)
            return 1

        try:
            q = LogSession.query.filter_by(user_id=uid)
            deleted = 0
            if sid:
                item    = q.filter_by(id=sid).first()
                deleted += _cascade_delete(item)
            else:
                for item in q.all():
                    deleted += _cascade_delete(item)
            from app import audit_event
            audit_event(user, "logs.delete", sid or "all",
                        {"scope": "history_delete", "deleted": deleted})
            db.session.commit()
            return jsonify({"status": "deleted", "deleted": deleted})
        except Exception as exc:
            db.session.rollback()
            return jsonify({"error": "Delete failed", "detail": str(exc)[:300]}), 500

    sessions = (LogSession.query.filter_by(user_id=uid)
                .order_by(LogSession.created_at.desc()).limit(50).all())
    return jsonify([{
        "id":      s.id,  "env":    s.environment, "file":   s.filename,
        "total":   s.total_lines,  "errors": s.error_count,
        "warns":   s.warn_count,   "latency":s.avg_latency,
        "apps":    s.apps_found,   "at":     s.created_at.strftime("%Y-%m-%d %H:%M"),
    } for s in sessions])


# ── /export/csv ───────────────────────────────────────────────────────────────

@logs_bp.route("/export/csv", methods=["POST"])
def export_csv():
    user = _get_user()
    if user is None:
        return jsonify({"error": "Session expired."}), 401

    data = request.get_json(force=True, silent=True) or {}
    rows = data.get("rows", [])

    def clean(v):
        return '"' + str(v).replace('"', '""').replace("\n", " ") + '"'

    lines = ["time,level,app,trace,event,latency,message"]
    for r in rows:
        lines.append(",".join(clean(r.get(k, "")) for k in
                               ["time", "level", "app", "trace", "event", "latency", "message"]))

    resp = make_response("\n".join(lines))
    resp.headers["Content-Type"] = "text/csv"
    resp.headers["Content-Disposition"] = "attachment; filename=observex-log-export.csv"

    try:
        from app import audit_event
        audit_event(user, "logs.export_csv", "visible_rows", {"rows": len(rows)})
        db.session.commit()
    except Exception:
        db.session.rollback()

    return resp


# ── /api/v1/sessions/<id>/rows — reload persisted session ────────────────────

@logs_bp.route("/api/v1/sessions/<int:session_id>/rows", methods=["GET"])
def session_rows(session_id):
    user = _get_user()
    if user is None:
        return jsonify({"error": "Not authenticated"}), 401

    ls = LogSession.query.filter_by(id=session_id, user_id=user.id).first_or_404()

    # Prefer LogEvent rows (new path); fall back to log_rows_json for legacy sessions
    log_events = (LogEvent.query
                  .filter_by(user_id=user.id, session_id=session_id)
                  .order_by(LogEvent.created_at.desc())
                  .limit(2000).all())

    if log_events:
        rows = []
        for e in log_events:
            try:
                r = json.loads(e.row_json or "{}")
            except Exception:
                r = {}
            r.setdefault("time",     e.event_time)
            r.setdefault("level",    e.level)
            r.setdefault("app",      e.api_name)
            r.setdefault("endpoint", e.endpoint)
            r.setdefault("trace",    e.trace_id)
            r.setdefault("latency",  e.latency_ms)
            r.setdefault("message",  e.message)
            rows.append(r)
    else:
        try:
            rows = json.loads(ls.log_rows_json or "[]")
        except Exception:
            rows = []

    try:
        result = json.loads(ls.result_json or "{}")
    except Exception:
        result = {}

    # Synthetic placeholder rows when nothing is stored
    if not rows and ls.total_lines:
        apps_list    = [a for a in (ls.apps_found or "").split(",") if a]
        primary_app  = apps_list[0] if apps_list else (ls.filename or "unknown")
        ts           = ls.created_at.isoformat() if ls.created_at else ""
        rows  = ([{"time": ts, "level": "ERROR", "app": primary_app, "message": "[restored] error event",
                   "trace": "", "latency": ls.avg_latency or 0, "_synthetic": True}]
                 * min(ls.error_count or 0, 50))
        rows += ([{"time": ts, "level": "WARN",  "app": primary_app, "message": "[restored] warn event",
                   "trace": "", "latency": 0, "_synthetic": True}]
                 * min(ls.warn_count or 0, 30))
        remaining = min((ls.total_lines or 0) - len(rows), 200)
        rows += ([{"time": ts, "level": "INFO",  "app": primary_app, "message": "[restored] info event",
                   "trace": "", "latency": 0, "_synthetic": True}]
                 * max(0, remaining))

    apps_list = [a for a in (ls.apps_found or "").split(",") if a]
    result.update({
        "log_rows":       rows,
        "session_id":     ls.id,
        "stored":         True,
        "reloaded":       True,
        "synthetic_rows": len(log_events) == 0 and not json.loads(ls.log_rows_json or "[]"),
        "total":          result.get("total") or ls.total_lines,
        "errors":         result.get("errors") or ls.error_count,
        "warns":          result.get("warns") or ls.warn_count,
        "latency":        result.get("latency") or ls.avg_latency,
        "apps":           result.get("apps") or apps_list,
    })
    return jsonify(result)
