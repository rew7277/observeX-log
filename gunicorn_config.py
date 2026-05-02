"""
gunicorn_config.py — ObserveX production gunicorn settings.

SSL POOL FIX: wrap dispose() in app.app_context() so Flask-SQLAlchemy
can reach db.engine. This works because --preload already imported the
app module in the parent before forking.
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
    Dispose the inherited connection pool in each worker after fork.
    Must use app.app_context() because db.engine is Flask-SQLAlchemy
    and requires an active application context to resolve the engine.
    close=False: leaves parent-process connections untouched.
    """
    try:
        import app as _app_module
        with _app_module.app.app_context():
            _app_module.db.engine.dispose(close=False)
        server.log.info(f"[worker {worker.pid}] DB pool disposed after fork ✓")
    except Exception as exc:
        server.log.warning(f"[worker {worker.pid}] post_fork warning: {exc}")

def worker_abort(worker):
    try:
        import app as _app_module
        with _app_module.app.app_context():
            _app_module.db.engine.dispose()
    except Exception:
        pass
