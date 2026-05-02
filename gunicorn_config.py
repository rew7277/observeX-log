"""
gunicorn_config.py — ObserveX production gunicorn settings.

FIX v2: post_fork must NOT import 'app' (no Flask context exists at fork time).
Instead, dispose the underlying SQLAlchemy engine directly via the module.
"""
import os

port    = os.environ.get("PORT", "8080")
bind    = f"0.0.0.0:{port}"
workers = int(os.environ.get("WEB_CONCURRENCY", "2"))
worker_class = "sync"
timeout      = 120
keepalive    = 5
max_requests = 1000
max_requests_jitter = 100
accesslog = "-"
errorlog  = "-"
loglevel  = "info"

def post_fork(server, worker):
    """
    Dispose the inherited DB connection pool in each forked worker.
    CRITICAL: Do NOT use 'from app import db' here — no Flask app context
    exists at fork time, which causes 'Working outside of application context'.
    Instead, reach the engine via SQLAlchemy's internals.
    """
    try:
        # Import the module (already loaded due to --preload), get the engine directly
        import app as _app_module
        engine = _app_module.db.engine
        engine.dispose(close=False)   # close=False: don't close parent's connections
        server.log.info(f"[worker {worker.pid}] DB pool disposed (SSL fix) ✓")
    except Exception as exc:
        server.log.warning(f"[worker {worker.pid}] post_fork dispose warning: {exc}")

def worker_abort(worker):
    try:
        import app as _app_module
        _app_module.db.engine.dispose()
    except Exception:
        pass
