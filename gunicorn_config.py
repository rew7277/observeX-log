"""
gunicorn_config.py — ObserveX production gunicorn settings v3.
"""
import os, warnings

# Suppress authlib joserfc migration warning.
# AuthlibDeprecationWarning is NOT a subclass of plain DeprecationWarning for filtering
# purposes via PYTHONWARNINGS or -W flags. Import and filter the actual class instead.
try:
    from authlib.deprecate import AuthlibDeprecationWarning as _AuthlibDepWarn
    warnings.filterwarnings("ignore", category=_AuthlibDepWarn)
except ImportError:
    pass

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
    """Dispose inherited SSL connection pool in each forked worker."""
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
