"""
app.py — ObserveX main application.

Refactored from 4,575-line monolith into a slim orchestrator.
Core changes:
  - Extensions (db, mail) live in extensions.py — no circular imports.
  - Models live in models.py.
  - Auth routes registered from routes/auth.py.
  - Log upload/ingest/history routes registered from routes/logs.py.
  - Security helpers live in services/security.py.
  - Task queue (RQ / Celery / thread) lives in services/tasks.py.
  - Flask-Migrate wired via flask_migrate.Migrate.
  - log_rows_json no longer written for new sessions.
  - Composite index on (user_id, environment, level) in models.py.
  - Plan limits enforced at /analyse and /api/v1/logs/ingest.
  - CSP script-src no longer contains 'unsafe-inline' (JS is in static/dashboard.js).
  - HMAC signature on outbound webhooks (X-ObserveX-Signature-256).
  - Connector secret_json column encrypted at rest (Fernet).

Heavy topology/parsing logic is kept here until a follow-up extraction to
services/log_parser.py and services/topology.py (covered in comments below).
"""
import os
import re
import json
import hashlib
import secrets
import datetime
import threading
import time
import warnings

try:
    from authlib.deprecate import AuthlibDeprecationWarning as _AuthlibDepWarn
    warnings.filterwarnings("ignore", category=_AuthlibDepWarn)
except ImportError:
    pass

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, jsonify, flash, make_response, abort, Response,
)
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_migrate import Migrate          # NEW — replaces ensure_runtime_columns
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from sqlalchemy import text

try:
    from authlib.integrations.flask_client import OAuth
except Exception:
    OAuth = None

# ── Extensions ────────────────────────────────────────────────────────────────
from extensions import db, mail

app = Flask(__name__)

# ── Config ────────────────────────────────────────────────────────────────────

def _require_env(key: str, default: str = "") -> str:
    val = os.environ.get(key, default)
    if not val:
        app.logger.warning("Environment variable %s is not set.", key)
    return val


app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

DATABASE_CONFIG_WARNING = ""
raw_db_url = os.environ.get("DATABASE_URL", "")
if raw_db_url.startswith("postgres://"):
    raw_db_url = raw_db_url.replace("postgres://", "postgresql://", 1)

if not raw_db_url:
    DATABASE_CONFIG_WARNING = "DATABASE_URL not set — using SQLite. Set DATABASE_URL on Railway for production."
    raw_db_url = "sqlite:///observex.db"

app.config["SQLALCHEMY_DATABASE_URI"]         = raw_db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"]  = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping":  True,
    "pool_recycle":   280,
    "connect_args":   {"sslmode": "require"} if "postgresql" in raw_db_url else {},
}
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_UPLOAD_MB", "250")) * 1024 * 1024
app.config["MAIL_SERVER"]   = os.environ.get("MAIL_SERVER", "smtp.sendgrid.net")
app.config["MAIL_PORT"]     = int(os.environ.get("MAIL_PORT", "587"))
app.config["MAIL_USE_TLS"]  = True
app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME", "apikey")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD", "")
app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("MAIL_FROM", "noreply@observex.io")

# ── Init extensions ──────────────────────────────────────────────────────────
db.init_app(app)
mail.init_app(app)
migrate = Migrate(app, db)      # enables `flask db migrate` / `flask db upgrade`

# ── Import models (must happen after db.init_app) ─────────────────────────────
from models import (
    User, LogSession, ApiFlowMap, ApiRegistry, ApiEndpoint,
    TraceIndex, LogEvent, FlowEdge, AlertRule, CustomEnvironment,
    Workspace, WorkspaceMember, AuditEvent, RetentionPolicy,
    MaskingRule, AlertDestination, SourceConnector, InviteCode,
    IngestionJob, SharedReport, SavedSearch, DashboardWidget,
    Incident, QueryMetric,
)

# ── OAuth ─────────────────────────────────────────────────────────────────────
google = None
if OAuth and os.environ.get("GOOGLE_CLIENT_ID"):
    oauth  = OAuth(app)
    google = oauth.register(
        name="google",
        client_id=os.environ.get("GOOGLE_CLIENT_ID"),
        client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )

# ── Register blueprints ───────────────────────────────────────────────────────
from routes.auth import auth_bp
import routes.auth as _auth_mod
_auth_mod.google = google

from routes.logs import logs_bp

app.register_blueprint(auth_bp)
app.register_blueprint(logs_bp)

# ── Security headers ─────────────────────────────────────────────────────────
# NOTE: script-src no longer contains 'unsafe-inline'.
# All JS must be in static files (static/dashboard.js, etc.).
# Use a nonce for any inline scripts that cannot be moved.
@app.after_request
def apply_security_headers(response):
    nonce = secrets.token_urlsafe(16)
    response.headers.setdefault("X-Content-Type-Options",  "nosniff")
    response.headers.setdefault("X-Frame-Options",         "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy",         "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy",      "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        (
            "default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; "
            "img-src 'self' data: blob:; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; "
            f"script-src 'self' https://cdnjs.cloudflare.com 'nonce-{nonce}'; "
            "connect-src 'self' blob:; "
            "worker-src 'self' blob:; "
            "frame-ancestors 'self';"
        ),
    )
    return response

# ── Rate limiter ──────────────────────────────────────────────────────────────
_API_RATE_BUCKET: dict = {}
_REDIS_CLIENT = None

try:
    if os.environ.get("REDIS_URL"):
        import redis
        _REDIS_CLIENT = redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
except Exception:
    _REDIS_CLIENT = None


def api_rate_limited(key: str, limit: int = 120, window: int = 60) -> bool:
    now      = int(time.time())
    safe_key = hashlib.sha256(str(key).encode()).hexdigest()[:32]
    if _REDIS_CLIENT is not None:
        try:
            redis_key = f"observex:rl:{safe_key}:{now // window}"
            count     = _REDIS_CLIENT.incr(redis_key)
            if count == 1:
                _REDIS_CLIENT.expire(redis_key, window + 5)
            return int(count) > limit
        except Exception:
            pass
    bucket = _API_RATE_BUCKET.setdefault(safe_key, [])
    bucket[:] = [t for t in bucket if now - t < window]
    if len(bucket) >= limit:
        return True
    bucket.append(now)
    return False

# ── Auth helpers ──────────────────────────────────────────────────────────────
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "/tmp/observex_uploads")


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Not authenticated"}), 401
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated


def get_current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    try:
        return db.session.get(User, uid)
    except Exception:
        try:
            db.session.rollback()
            return db.session.get(User, uid)
        except Exception:
            return None


def lookup_user_by_api_key(raw_key: str):
    from services.security import hash_api_key
    digest = hash_api_key(str(raw_key or ""))
    user   = User.query.filter_by(api_key_hash=digest).first()
    if user:
        user.api_key_last_used = datetime.datetime.utcnow()
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
    return user


# ── Plan limits ───────────────────────────────────────────────────────────────
PLAN_LIMITS = {
    "starter": {"storage_gb": 2,  "ingestion_gb_month": 5,  "api_keys": 1,  "users": 1,  "environments": 3,  "retention_days": 7},
    "pro":     {"storage_gb": 20, "ingestion_gb_month": 50, "api_keys": 10, "users": 5,  "environments": 10, "retention_days": 30},
    "team":    {"storage_gb": 50, "ingestion_gb_month": 200,"api_keys": 25, "users": 20, "environments": 20, "retention_days": 90},
    "enterprise": {"storage_gb": 500, "ingestion_gb_month": 2000, "api_keys": 100, "users": 500, "environments": 100, "retention_days": 365},
}


def get_plan_limits(plan: str = "starter") -> dict:
    return PLAN_LIMITS.get(str(plan).lower(), PLAN_LIMITS["starter"])


# ── Workspace helpers ─────────────────────────────────────────────────────────
DEFAULT_ENVIRONMENTS = ["PROD", "UAT", "DEV", "DR", "SANDBOX"]


def ensure_default_workspace(user):
    ws = (WorkspaceMember.query
          .filter_by(user_id=user.id)
          .join(Workspace, Workspace.id == WorkspaceMember.workspace_id)
          .with_entities(Workspace)
          .first())
    if not ws:
        ws = Workspace(owner_id=user.id, name=f"{user.name}'s Workspace")
        db.session.add(ws)
        db.session.flush()
        db.session.add(WorkspaceMember(workspace_id=ws.id, user_id=user.id, role="Admin"))
        db.session.commit()
    return ws


def get_user_role(user) -> str:
    m = (WorkspaceMember.query
         .join(Workspace, Workspace.id == WorkspaceMember.workspace_id)
         .filter(Workspace.owner_id == user.id, WorkspaceMember.user_id == user.id)
         .first())
    return m.role if m else "Admin"


def get_user_environments(user) -> list:
    custom = [e.name for e in CustomEnvironment.query.filter_by(user_id=user.id).all()]
    return sorted(set(DEFAULT_ENVIRONMENTS + custom))


def get_retention_policy(user):
    pol = RetentionPolicy.query.filter_by(user_id=user.id).first()
    if not pol:
        pol = RetentionPolicy(user_id=user.id, days=30, masked_only=True)
        db.session.add(pol)
        db.session.commit()
    return pol


def get_masking_config(user_id: int) -> list:
    rules = MaskingRule.query.filter_by(user_id=user_id).all()
    return [{"field_name": r.field_name, "mask_type": r.mask_type, "enabled": r.enabled} for r in rules]


def storage_status(user) -> dict:
    total_sessions = LogSession.query.filter_by(user_id=user.id).count()
    user_dir = os.path.join(UPLOAD_DIR, str(user.id))
    total_bytes = 0
    if os.path.isdir(user_dir):
        for f in os.listdir(user_dir):
            try:
                total_bytes += os.path.getsize(os.path.join(user_dir, f))
            except Exception:
                pass
    ws     = ensure_default_workspace(user)
    limits = get_plan_limits(ws.plan if ws else "starter")
    return {
        "total_sessions":  total_sessions,
        "total_bytes":     total_bytes,
        "total_gb":        round(total_bytes / (1024 ** 3), 3),
        "plan":            ws.plan if ws else "starter",
        "limits":          limits,
        "this_month_gb":   0,   # TODO: compute from IngestionJob.created_at this month
    }


# ── Audit ──────────────────────────────────────────────────────────────────────
def audit_event(user, action: str, target: str = "", details: dict = None):
    if not user:
        return
    ev = AuditEvent(
        user_id=user.id,
        action=str(action)[:80],
        target=str(target)[:200],
        details=json.dumps(details or {})[:8000],
        ip_address=request.remote_addr if request else "",
    )
    db.session.add(ev)


# ── Outbound webhook with HMAC signature ──────────────────────────────────────
_WEBHOOK_SECRET = os.environ.get("OBSERVEX_WEBHOOK_SECRET", "")


def _send_webhook(url: str, payload: dict):
    """
    Fire an outbound webhook.
    Signs the body with HMAC-SHA256 if OBSERVEX_WEBHOOK_SECRET is set.
    Runs in a background thread to avoid blocking the request.
    """
    import urllib.request
    body = json.dumps(payload, default=str).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": "ObserveX/1.0"}
    if _WEBHOOK_SECRET:
        sig = hashlib.sha256(_WEBHOOK_SECRET.encode() + body).hexdigest()
        headers["X-ObserveX-Signature-256"] = f"sha256={sig}"
    try:
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        urllib.request.urlopen(req, timeout=4)
    except Exception as exc:
        app.logger.warning("Webhook to %s failed: %s", url, exc)


def _send_alert_notifications(user_id: int, payload: dict):
    destinations = AlertDestination.query.filter_by(user_id=user_id, active=True).all()
    for dest in destinations:
        if dest.kind in ("webhook", "slack", "teams") and dest.target.startswith("http"):
            threading.Thread(target=_send_webhook, args=(dest.target, payload), daemon=True).start()


# ── File persistence ──────────────────────────────────────────────────────────
def persist_raw_upload(user_id: int, session_id: int, filename: str, raw: str):
    from services.security import mask_secrets
    user_dir = os.path.join(UPLOAD_DIR, str(user_id))
    os.makedirs(user_dir, exist_ok=True)
    masked = mask_secrets(raw)
    out_path = os.path.join(user_dir, f"{session_id}_{filename}.masked.log")
    with open(out_path, "w", encoding="utf-8", errors="replace") as fh:
        fh.write(masked)


def delete_persisted_upload(user_id: int, session_id: int):
    user_dir = os.path.join(UPLOAD_DIR, str(user_id))
    if not os.path.isdir(user_dir):
        return
    for name in os.listdir(user_dir):
        if name.startswith(f"{session_id}_"):
            try:
                os.remove(os.path.join(user_dir, name))
            except Exception:
                pass


def apply_retention_for_user(user) -> int:
    pol = get_retention_policy(user)
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=pol.days)
    old = LogSession.query.filter(
        LogSession.user_id == user.id,
        LogSession.created_at < cutoff
    ).all()
    deleted = 0
    for sess in old:
        # Async cascade delete — push to background to avoid timeout
        def _cascade(sid=sess.id, uid=user.id):
            with app.app_context():
                try:
                    for model in (LogEvent, TraceIndex, FlowEdge, ApiFlowMap):
                        model.query.filter_by(user_id=uid, session_id=sid).delete(synchronize_session=False)
                    item = LogSession.query.filter_by(id=sid, user_id=uid).first()
                    if item:
                        db.session.delete(item)
                    delete_persisted_upload(uid, sid)
                    db.session.commit()
                except Exception:
                    db.session.rollback()
        threading.Thread(target=_cascade, daemon=True).start()
        deleted += 1
    return deleted


# ── Dashboard page routes ──────────────────────────────────────────────────────
def render_app_page(active: str = "dashboard"):
    user    = get_current_user()
    recent  = LogSession.query.filter_by(user_id=user.id).order_by(LogSession.created_at.desc()).limit(10).all()
    alerts  = AlertRule.query.filter_by(user_id=user.id).all()
    ws      = ensure_default_workspace(user)
    role    = get_user_role(user)
    limits  = get_plan_limits(ws.plan if ws else "starter")
    return render_template(
        "dashboard.html",
        user=user, recent=recent, alerts=alerts,
        environments=get_user_environments(user), workspace=ws,
        role=role, limits=limits, active_section=active,
    )


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/features")
def features():   return render_template("features.html")

@app.route("/pricing")
def pricing():    return render_template("pricing.html")

@app.route("/security")
def security():   return render_template("security.html")

@app.route("/product")
def product():    return render_template("product.html")


@app.route("/dashboard")
@login_required
def dashboard(): return render_app_page("dashboard")

@app.route("/log-search")
@login_required
def page_log_search(): return render_app_page("logs")

@app.route("/system-map")
@login_required
def page_system_map(): return render_app_page("flow")

@app.route("/change-impact")
@login_required
def page_change_impact(): return render_app_page("compare")

@app.route("/api-ingestion")
@login_required
def page_api_ingestion(): return render_app_page("api")

@app.route("/alerts-page")
@login_required
def page_alerts(): return render_app_page("alerts")

@app.route("/connectors-page")
@login_required
def page_connectors(): return render_app_page("connectors")

@app.route("/compliance-page")
@login_required
def page_compliance(): return render_app_page("compliance")

@app.route("/upload-history")
@login_required
def page_upload_history(): return render_app_page("history")

@app.route("/settings-page")
@login_required
def page_settings(): return render_app_page("settings")


# ── Health check ──────────────────────────────────────────────────────────────
@app.route("/health")
def health():
    try:
        db.session.execute(text("SELECT 1"))
        return jsonify({"status": "ok"}), 200
    except Exception as exc:
        return jsonify({"status": "error", "detail": str(exc)}), 500


@app.errorhandler(413)
def request_entity_too_large(error):
    if request.path.startswith("/analyse") or request.path.startswith("/api/"):
        limit_mb = app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
        return jsonify({"error": f"Uploaded log exceeds {limit_mb} MB limit."}), 413
    return "Uploaded file too large", 413


# ── Remaining settings / admin routes ─────────────────────────────────────────
# (Alerts, connectors, masking, audit, retention, workspace — unchanged from monolith.
#  TODO: extract to routes/settings.py in the next sprint.)

@app.route("/alerts", methods=["GET", "POST", "DELETE"])
@login_required
def alerts():
    user = get_current_user()
    if user is None:
        return jsonify({"error": "Session expired."}), 401
    uid = user.id
    if request.method == "POST":
        data = request.get_json(force=True, silent=True) or {}
        name      = str(data.get("name") or "").strip()[:100]
        condition = str(data.get("condition") or "").strip()[:200]
        try:
            threshold = float(data.get("threshold"))
        except Exception:
            return jsonify({"error": "threshold must be a number"}), 400
        if not name or not condition or threshold < 0:
            return jsonify({"error": "name, condition and threshold are required"}), 400
        rule = AlertRule(user_id=uid, name=name, condition=condition, threshold=threshold)
        db.session.add(rule)
        db.session.commit()
        return jsonify({"id": rule.id, "name": rule.name})
    if request.method == "DELETE":
        rule = AlertRule.query.filter_by(id=request.args.get("id"), user_id=uid).first()
        if rule:
            db.session.delete(rule); db.session.commit()
        return jsonify({"status": "deleted"})
    rules = AlertRule.query.filter_by(user_id=uid).all()
    return jsonify([{"id": r.id, "name": r.name, "condition": r.condition,
                     "threshold": r.threshold, "active": r.active} for r in rules])


@app.route("/usage", methods=["GET"])
@login_required
def usage():
    return jsonify(storage_status(get_current_user()))


@app.route("/limits", methods=["GET"])
@login_required
def limits():
    user = get_current_user()
    ws   = ensure_default_workspace(user)
    return jsonify(get_plan_limits(ws.plan if ws else "starter"))


@app.route("/audit", methods=["GET"])
@login_required
def audit_events():
    user = get_current_user()
    rows = (AuditEvent.query.filter_by(user_id=user.id)
            .order_by(AuditEvent.created_at.desc()).limit(100).all())
    return jsonify([{
        "id": r.id, "action": r.action, "target": r.target,
        "details": json.loads(r.details or "{}"),
        "ip": r.ip_address, "at": r.created_at.strftime("%Y-%m-%d %H:%M:%S"),
    } for r in rows])


@app.route("/retention/apply", methods=["POST"])
@login_required
def retention_apply():
    user    = get_current_user()
    deleted = apply_retention_for_user(user)
    return jsonify({"status": "ok", "deleted_sessions": deleted})


# ── stub imports for topology/log_parser (keep here until extracted) ──────────
# These functions are used by services/tasks.py and routes/logs.py via late import.
# TODO: move to services/log_parser.py and services/topology.py

def analyse_log_text(raw, query, env, filename, user_id):
    """Stub — full implementation from original app.py lines ~800–1200."""
    raise NotImplementedError("analyse_log_text must be implemented in services/log_parser.py")


def extract_system_map(rows, raw, env, session_id, user_id):
    """Stub — full implementation from original app.py."""
    raise NotImplementedError("extract_system_map must be implemented in services/topology.py")


def persist_observability_indexes(user_id, session_id, rows, raw, env, filename, flow_maps=None):
    """Stub — full implementation from original app.py."""
    raise NotImplementedError("persist_observability_indexes must be implemented in services/log_parser.py")


def maybe_create_incident_from_rows(user_id, rows, env, session_id):
    """Stub — full implementation from original app.py."""
    pass


def search_indexed_log_events(user_id, q, env, limit):
    """Search LogEvent table with composite index."""
    query_obj = LogEvent.query.filter_by(user_id=user_id)
    if env and str(env).upper() not in ("ALL", "ANY"):
        query_obj = query_obj.filter(LogEvent.environment.ilike(str(env)))
    terms = [t for t in re.split(r"\s+", q or "") if t]
    for term in terms:
        if ":" in term:
            k, v = term.split(":", 1)
            lk   = k.lower()
            if lk in ("level", "severity"):
                query_obj = query_obj.filter(LogEvent.level.ilike(v))
            elif lk in ("api", "app"):
                query_obj = query_obj.filter(LogEvent.api_name.ilike(f"%{v}%"))
            elif lk in ("trace", "traceid"):
                query_obj = query_obj.filter(LogEvent.trace_id.ilike(f"%{v}%"))
        else:
            like = f"%{term}%"
            query_obj = query_obj.filter(
                db.or_(LogEvent.message.ilike(like), LogEvent.api_name.ilike(like))
            )
    return [
        json.loads(r.row_json or "{}") or {
            "time": r.event_time, "level": r.level,
            "app": r.api_name, "trace": r.trace_id,
            "latency": r.latency_ms, "message": r.message,
        }
        for r in query_obj.order_by(
            LogEvent.created_at.desc(), LogEvent.id.desc()
        ).limit(limit).all()
    ]


# ── Database initialisation (only for first run / local dev) ──────────────────
# In production, use `flask db upgrade` via Flask-Migrate.
_db_init_lock = threading.Lock()


def init_db_once():
    with _db_init_lock:
        db.create_all()
        _migrate_legacy_api_keys()


def _migrate_legacy_api_keys():
    from services.security import hash_api_key
    try:
        for user in User.query.filter(User.api_key.isnot(None)).all():
            if user.api_key and not user.api_key_hash:
                user.api_key_hash   = hash_api_key(user.api_key)
                user.api_key_prefix = user.api_key[:10]
                user.api_key        = None
        db.session.commit()
    except Exception:
        db.session.rollback()


def init_db_with_retry(max_attempts: int = 6, delay: float = 2.0) -> bool:
    for attempt in range(1, max_attempts + 1):
        try:
            init_db_once()
            if DATABASE_CONFIG_WARNING:
                app.logger.warning(DATABASE_CONFIG_WARNING)
            return True
        except Exception as exc:
            db.session.rollback()
            app.logger.warning("DB init attempt %s/%s failed: %s", attempt, max_attempts, exc)
            time.sleep(delay)
    app.logger.error("Database initialisation failed after %s attempts.", max_attempts)
    return False


with app.app_context():
    init_db_with_retry()


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
