"""
gunicorn_config.py — ObserveX production gunicorn settings
Fixes SSL connection pool corruption when using --preload with PostgreSQL.
"""
import os

# ── Binding ──────────────────────────────────────────────────────────────────
port   = os.environ.get("PORT", "8080")
bind   = f"0.0.0.0:{port}"

# ── Workers ───────────────────────────────────────────────────────────────────
workers        = int(os.environ.get("WEB_CONCURRENCY", "2"))
worker_class   = "sync"
timeout        = 120
keepalive      = 5
max_requests   = 1000          # recycle workers to prevent memory leaks
max_requests_jitter = 100

# ── Logging ───────────────────────────────────────────────────────────────────
accesslog      = "-"
errorlog       = "-"
loglevel       = "info"

# ── CRITICAL: SSL connection pool fix ────────────────────────────────────────
# When gunicorn forks workers, child processes inherit the parent's open SSL
# sockets. Using that same socket from two processes causes SSL MAC errors.
# post_fork() disposes the inherited pool so each worker creates fresh connections.
def post_fork(server, worker):
    """Called in the child after fork — dispose inherited DB connections."""
    try:
        from app import db
        db.engine.dispose()
        server.log.info(f"[worker {worker.pid}] DB connection pool disposed after fork ✓")
    except Exception as exc:
        server.log.warning(f"[worker {worker.pid}] post_fork pool dispose failed: {exc}")

def worker_abort(worker):
    """Called when a worker is aborted — ensure clean DB teardown."""
    try:
        from app import db
        db.engine.dispose()
    except Exception:
        pass
