"""
services/tasks.py — Async task queue for ObserveX.

Strategy:
  - If REDIS_URL is set and rq is installed → use RQ (simple, no broker config needed).
  - If celery is installed and CELERY_BROKER_URL is set → use Celery.
  - Otherwise → fall back to daemon thread (same as before, safe for Railway Basic).

Usage in routes:
    from services.tasks import enqueue_ingestion
    job_record = enqueue_ingestion(user_id, raw, query, env, filename)
"""
import os
import logging
import threading

logger = logging.getLogger(__name__)

# ── Strategy detection ────────────────────────────────────────────────────────

_REDIS_URL   = os.environ.get("REDIS_URL", "").strip()
_CELERY_URL  = os.environ.get("CELERY_BROKER_URL", "").strip()
_USE_RQ      = False
_USE_CELERY  = False
_rq_queue    = None
_celery_app  = None

if _REDIS_URL:
    try:
        from rq import Queue
        import redis as _redis_lib
        _conn = _redis_lib.from_url(_REDIS_URL, decode_responses=False)
        _rq_queue = Queue("observex-ingestion", connection=_conn, default_timeout=1800)
        _USE_RQ = True
        logger.info("ObserveX task backend: RQ (Redis)")
    except ImportError:
        logger.warning("REDIS_URL is set but rq is not installed. Add rq to requirements.txt.")
    except Exception as exc:
        logger.warning("RQ setup failed: %s. Falling back to thread.", exc)

if not _USE_RQ and _CELERY_URL:
    try:
        from celery import Celery
        _celery_app = Celery("observex", broker=_CELERY_URL,
                             backend=os.environ.get("CELERY_RESULT_BACKEND", _CELERY_URL))
        _celery_app.conf.task_serializer = "json"
        _celery_app.conf.result_serializer = "json"
        _celery_app.conf.accept_content = ["json"]
        _USE_CELERY = True
        logger.info("ObserveX task backend: Celery (%s)", _CELERY_URL)
    except ImportError:
        logger.warning("CELERY_BROKER_URL set but celery not installed.")
    except Exception as exc:
        logger.warning("Celery setup failed: %s. Falling back to thread.", exc)

if not _USE_RQ and not _USE_CELERY:
    logger.warning(
        "ObserveX task backend: daemon thread (single-worker, not production-safe). "
        "Set REDIS_URL and install rq for a proper queue."
    )


# ── Shared ingestion worker function ─────────────────────────────────────────
# This function is called regardless of the backend.

def _run_ingestion(job_id: int, user_id: int, raw: str, query: str, env: str, filename: str):
    """
    Worker function: parse logs, persist session, build topology, write indexes.
    Runs inside RQ worker, Celery worker, or daemon thread.
    """
    # Import here so this module can be imported before the Flask app is fully built.
    from app import app  # noqa: F401  (we need the app context)
    with app.app_context():
        # Inline import to avoid circular imports at module level
        from extensions import db
        from models import IngestionJob, LogSession
        from services.log_parser import analyse_log_text
        import json, datetime, time

        job = db.session.get(IngestionJob, job_id)
        if not job:
            return

        try:
            job.status     = "running"
            job.progress   = 10
            job.started_at = datetime.datetime.utcnow()
            db.session.commit()

            # For very large files: analyse first 10 MB, count the rest cheaply.
            RAW_LIMIT  = int(os.environ.get("OBSERVEX_PARSE_LIMIT_BYTES", str(10 * 1024 * 1024)))
            raw_sample = raw[:RAW_LIMIT]
            extra_lines  = 0
            extra_errors = 0
            if len(raw) > RAW_LIMIT:
                overflow    = raw[RAW_LIMIT:]
                extra_lines = overflow.count("\n")
                extra_errors = (
                    overflow.lower().count("level=error")
                    + overflow.count('"level":"error"')
                    + overflow.count(" ERROR ")
                )
                job.progress = 15
                db.session.commit()

            result = analyse_log_text(raw_sample, query, env, filename, user_id)
            if extra_lines:
                result["total"]  = result.get("total", 0) + extra_lines
                result["errors"] = result.get("errors", 0) + extra_errors

            job.progress = 45
            db.session.commit()

            rows_to_store  = result.get("log_rows", [])[:5000]
            result_summary = {k: v for k, v in result.items() if k != "log_rows"}

            ls = LogSession(
                user_id=user_id, environment=env, filename=filename,
                total_lines=result["total"], error_count=result["errors"],
                warn_count=result["warns"], avg_latency=result["latency"],
                apps_found=",".join(result["apps"]),
                log_rows_json="[]",   # NEW: rows go to LogEvent, not this column
                result_json=json.dumps(result_summary, default=str),
            )
            db.session.add(ls)
            db.session.flush()

            job.session_id  = ls.id
            job.total_lines = result.get("total", 0)
            job.progress    = 60
            db.session.commit()

            # Import topology/index services late to avoid circular imports
            from app import (  # noqa: F401
                extract_system_map,
                persist_observability_indexes,
                maybe_create_incident_from_rows,
                persist_raw_upload,
                audit_event,
                QueryMetric,
            )
            from models import User

            flow_maps = extract_system_map(rows_to_store, raw, env, ls.id, user_id)
            for fm in flow_maps:
                db.session.add(fm)

            persist_observability_indexes(user_id, ls.id, rows_to_store, raw, env, filename, flow_maps)
            job.progress = 85
            db.session.commit()

            maybe_create_incident_from_rows(user_id, rows_to_store, env, ls.id)
            persist_raw_upload(user_id, ls.id, filename, raw)

            job.status      = "success"
            job.total_lines = result.get("total", 0)
            job.session_id  = ls.id
            job.progress    = 100
            job.finished_at = datetime.datetime.utcnow()
            db.session.commit()

        except Exception as exc:
            db.session.rollback()
            logger.exception("Ingestion job %s failed", job_id)
            job = db.session.get(IngestionJob, job_id)
            if job:
                job.status      = "failed"
                job.error       = str(exc)[:4000]
                job.progress    = 100
                job.finished_at = datetime.datetime.utcnow()
                db.session.commit()


# ── Celery task wrapper (only registered if Celery is available) ──────────────

if _USE_CELERY and _celery_app:
    @_celery_app.task(name="observex.ingest", bind=True, max_retries=2)
    def _celery_ingest_task(self, job_id, user_id, raw, query, env, filename):
        try:
            _run_ingestion(job_id, user_id, raw, query, env, filename)
        except Exception as exc:
            raise self.retry(exc=exc, countdown=10)


# ── Public API ────────────────────────────────────────────────────────────────

def enqueue_ingestion(job_id: int, user_id: int, raw: str, query: str, env: str, filename: str):
    """
    Dispatch an ingestion job to the best available backend.
    job_id must already exist in the IngestionJob table before calling this.
    """
    if _USE_RQ:
        _rq_queue.enqueue(
            _run_ingestion,
            job_id, user_id, raw, query, env, filename,
            job_timeout=1800,
        )
        logger.info("Enqueued ingestion job %s → RQ", job_id)

    elif _USE_CELERY:
        _celery_ingest_task.apply_async(
            args=[job_id, user_id, raw, query, env, filename],
            countdown=0,
        )
        logger.info("Enqueued ingestion job %s → Celery", job_id)

    else:
        # Thread fallback — same as before; safe on Railway Basic single-dyno
        t = threading.Thread(
            target=_run_ingestion,
            args=(job_id, user_id, raw, query, env, filename),
            daemon=True,
        )
        t.start()
        logger.info("Dispatched ingestion job %s → daemon thread", job_id)


def send_alert_async(user_id: int, payload: dict):
    """
    Fire alert notifications off the request thread.
    Uses the same backend as ingestion so the pattern is consistent.
    """
    def _send():
        from app import app
        with app.app_context():
            from app import _send_alert_notifications
            _send_alert_notifications(user_id, payload)

    if _USE_RQ:
        from rq import Queue
        import redis as _redis_lib
        q = Queue("observex-alerts", connection=_redis_lib.from_url(_REDIS_URL, decode_responses=False), default_timeout=30)
        q.enqueue(_send)
    elif _USE_CELERY:
        # Wrap in a simple task; for now just thread-dispatch.
        threading.Thread(target=_send, daemon=True).start()
    else:
        threading.Thread(target=_send, daemon=True).start()
