import os, re, json, hashlib, secrets, datetime, threading, time
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, jsonify, flash, make_response
)
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps

try:
    from authlib.integrations.flask_client import OAuth
except Exception:
    OAuth = None

app = Flask(__name__)

# ── Web/API security hardening ───────────────────────────────────────────────
@app.after_request
def apply_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Content-Security-Policy", "default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; script-src 'self' 'unsafe-inline'; connect-src 'self'")
    return response

_API_RATE_BUCKET = {}
def api_rate_limited(key, limit=120, window=60):
    now = int(time.time())
    bucket = _API_RATE_BUCKET.setdefault(key, [])
    bucket[:] = [t for t in bucket if now - t < window]
    if len(bucket) >= limit:
        return True
    bucket.append(now)
    return False


# ── Config ────────────────────────────────────────────────────────────────────
_secret_key = os.environ.get("SECRET_KEY", "")
if not _secret_key:
    _secret_key = secrets.token_hex(32)
    app.logger.warning("SECRET_KEY env var is not set. Sessions will be invalidated on every restart. Set SECRET_KEY in Railway variables before production.")
app.config["SECRET_KEY"] = _secret_key
# Railway PostgreSQL
_database_url = os.environ.get("DATABASE_URL", "sqlite:///observex.db").strip()
if _database_url.startswith("postgres://"):
    _database_url = _database_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = _database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True, "pool_recycle": int(os.environ.get("DB_POOL_RECYCLE", "280"))}
if _database_url.startswith("postgresql"):
    app.config["SQLALCHEMY_ENGINE_OPTIONS"].update({"pool_size": int(os.environ.get("DB_POOL_SIZE", "5")), "max_overflow": int(os.environ.get("DB_MAX_OVERFLOW", "10")), "connect_args": {"sslmode": os.environ.get("PGSSLMODE", "prefer")}})
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_UPLOAD_MB", "500")) * 1024 * 1024
MAX_ANALYSE_LINES = int(os.environ.get("MAX_ANALYSE_LINES", "250000"))
MAX_PERSIST_CHARS = int(os.environ.get("MAX_PERSIST_CHARS", "8000000"))
SKIP_PERSIST_RAW = os.environ.get("SKIP_PERSIST_RAW", "0").lower() in {"1", "true", "yes"}

# Mail (configure via env vars in Railway)
app.config["MAIL_SERVER"]   = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
app.config["MAIL_PORT"]     = int(os.environ.get("MAIL_PORT", 587))
app.config["MAIL_USE_TLS"]  = True
app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME", "")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD", "")
app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("MAIL_USERNAME", "noreply@observex.io")

db   = SQLAlchemy(app)
mail = Mail(app)

# Optional Google OAuth. Set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET and GOOGLE_REDIRECT_URI in Railway.
oauth = OAuth(app) if OAuth else None
google = None
if oauth and os.environ.get("GOOGLE_CLIENT_ID") and os.environ.get("GOOGLE_CLIENT_SECRET"):
    google = oauth.register(
        name="google",
        client_id=os.environ.get("GOOGLE_CLIENT_ID"),
        client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )

ALLOWED_EXT = {"log", "txt", "json"}

# Railway volume/persistent storage. Mount a Railway volume and set OBSERVEX_DATA_DIR=/data.
DATA_DIR = os.environ.get("OBSERVEX_DATA_DIR", "/data")
UPLOAD_DIR = os.path.join(DATA_DIR, "observex_uploads")

# Optional MongoDB support. Keep empty to use Railway volume + SQLite only.
# For Railway Basic, prefer MongoDB Atlas over running MongoDB inside the Railway service.
MONGO_URI = os.environ.get("MONGO_URI", "").strip()
MONGO_DB_NAME = os.environ.get("MONGO_DB_NAME", "observex")
_mongo_client = None

def get_mongo_db():
    global _mongo_client
    if not MONGO_URI:
        return None
    try:
        from pymongo import MongoClient
        if _mongo_client is None:
            _mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=2500)
        return _mongo_client[MONGO_DB_NAME]
    except Exception:
        app.logger.exception("MongoDB is configured but unavailable")
        return None
try:
    os.makedirs(UPLOAD_DIR, exist_ok=True)
except Exception:
    # Local environments without /data can still run.
    UPLOAD_DIR = os.path.join(os.getcwd(), "observex_uploads")
    os.makedirs(UPLOAD_DIR, exist_ok=True)

# ── Models ────────────────────────────────────────────────────────────────────
class User(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    name          = db.Column(db.String(100), nullable=False)
    email         = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    reset_token   = db.Column(db.String(100), nullable=True)
    reset_expires = db.Column(db.DateTime, nullable=True)
    created_at    = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    api_key       = db.Column(db.String(64), default=lambda: secrets.token_hex(32))

class LogSession(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey("user.id"))
    environment = db.Column(db.String(20))
    filename    = db.Column(db.String(200))
    total_lines = db.Column(db.Integer, default=0)
    error_count = db.Column(db.Integer, default=0)
    warn_count  = db.Column(db.Integer, default=0)
    avg_latency = db.Column(db.Integer, default=0)
    apps_found  = db.Column(db.Text, default="")
    created_at  = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class AlertRule(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("user.id"))
    name       = db.Column(db.String(100))
    condition  = db.Column(db.String(200))
    threshold  = db.Column(db.Float)
    active     = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class AlertFiring(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    rule_id     = db.Column(db.Integer, db.ForeignKey("alert_rule.id"), nullable=True)
    rule_name   = db.Column(db.String(100), default="")
    condition   = db.Column(db.String(100), default="")
    value       = db.Column(db.Float, default=0)
    threshold   = db.Column(db.Float, default=0)
    session_id  = db.Column(db.Integer, default=0)
    environment = db.Column(db.String(30), default="")
    notified    = db.Column(db.Boolean, default=False)
    fired_at    = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class CustomEnvironment(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    name       = db.Column(db.String(40), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    __table_args__ = (db.UniqueConstraint("user_id", "name", name="uq_user_environment"),)

class Workspace(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    owner_id   = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    name       = db.Column(db.String(120), nullable=False)
    plan       = db.Column(db.String(40), default="starter")
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class WorkspaceMember(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    workspace_id = db.Column(db.Integer, db.ForeignKey("workspace.id"), nullable=False)
    user_id      = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    role         = db.Column(db.String(30), default="Admin")  # Admin, Developer, Viewer, Auditor
    created_at   = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    __table_args__ = (db.UniqueConstraint("workspace_id", "user_id", name="uq_workspace_user"),)

class AuditEvent(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    workspace_id = db.Column(db.Integer, nullable=True)
    action       = db.Column(db.String(80), nullable=False)
    target       = db.Column(db.String(200), default="")
    details      = db.Column(db.Text, default="{}")
    ip_address   = db.Column(db.String(80), default="")
    created_at   = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class RetentionPolicy(db.Model):
    id                 = db.Column(db.Integer, primary_key=True)
    user_id            = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    days               = db.Column(db.Integer, default=30)
    masked_only        = db.Column(db.Boolean, default=True)
    encrypted_raw_logs = db.Column(db.Boolean, default=False)
    created_at         = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at         = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class AlertDestination(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    kind        = db.Column(db.String(30), default="email")  # email, slack, teams, webhook
    target      = db.Column(db.String(300), nullable=False)
    active      = db.Column(db.Boolean, default=True)
    created_at  = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class SourceConnector(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    kind        = db.Column(db.String(40), nullable=False)  # s3, cloudwatch, mulesoft, kafka, webhook
    name        = db.Column(db.String(120), nullable=False)
    config_json = db.Column(db.Text, default="{}")  # store non-secret config only in MVP
    active      = db.Column(db.Boolean, default=True)
    created_at  = db.Column(db.DateTime, default=datetime.datetime.utcnow)


class InviteCode(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    workspace_id = db.Column(db.Integer, db.ForeignKey("workspace.id"), nullable=False)
    code         = db.Column(db.String(64), unique=True, nullable=False)
    role         = db.Column(db.String(30), default="Developer")
    active       = db.Column(db.Boolean, default=True)
    created_by   = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at   = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class IngestionJob(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    source      = db.Column(db.String(60), default="file")
    filename    = db.Column(db.String(220), default="")
    status      = db.Column(db.String(30), default="queued")  # queued, running, success, failed
    total_bytes = db.Column(db.Integer, default=0)
    total_lines = db.Column(db.Integer, default=0)
    error       = db.Column(db.Text, default="")
    started_at  = db.Column(db.DateTime, nullable=True)
    finished_at = db.Column(db.DateTime, nullable=True)
    created_at  = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class SharedReport(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    token       = db.Column(db.String(80), unique=True, nullable=False)
    title       = db.Column(db.String(180), default="ObserveX RCA Report")
    content     = db.Column(db.Text, default="")
    expires_at  = db.Column(db.DateTime, nullable=False)
    created_at  = db.Column(db.DateTime, default=datetime.datetime.utcnow)


class SavedSearch(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    title      = db.Column(db.String(140), nullable=False)
    query      = db.Column(db.String(500), default="")
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class DashboardWidget(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    title      = db.Column(db.String(140), nullable=False)
    widget_type= db.Column(db.String(80), default="Errors")
    config_json= db.Column(db.Text, default="{}")
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Incident(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    user_id       = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    title         = db.Column(db.String(220), nullable=False)
    severity      = db.Column(db.Integer, default=0)
    impacted_apis = db.Column(db.String(500), default="")
    owner         = db.Column(db.String(120), default="")
    status        = db.Column(db.String(40), default="Open")
    notes         = db.Column(db.Text, default="")
    evidence_json = db.Column(db.Text, default="[]")
    created_at    = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at    = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class QueryMetric(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    action      = db.Column(db.String(80), default="search")
    duration_ms = db.Column(db.Integer, default=0)
    rows        = db.Column(db.Integer, default=0)
    bytes       = db.Column(db.Integer, default=0)
    created_at  = db.Column(db.DateTime, default=datetime.datetime.utcnow)


def ensure_default_workspace(user):
    if user is None:
        return None
    ws = Workspace.query.filter_by(owner_id=user.id).order_by(Workspace.id.asc()).first()
    if not ws:
        ws = Workspace(owner_id=user.id, name=f"{user.name or 'My'} Workspace")
        db.session.add(ws)
        db.session.flush()
        db.session.add(WorkspaceMember(workspace_id=ws.id, user_id=user.id, role="Admin"))
        db.session.flush()
    return ws

def get_user_role(user):
    ws = ensure_default_workspace(user)
    if not ws:
        return "Viewer"
    m = WorkspaceMember.query.filter_by(workspace_id=ws.id, user_id=user.id).first()
    return m.role if m else "Viewer"

def role_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        def inner(*args, **kwargs):
            user = get_current_user()
            if user is None:
                return jsonify({"error":"Session expired. Please login again."}), 401
            if get_user_role(user) not in roles:
                return jsonify({"error":"Not allowed for your role."}), 403
            return fn(*args, **kwargs)
        return inner
    return wrapper

def audit_event(user, action, target="", details=None):
    if user is None:
        return
    try:
        ws = ensure_default_workspace(user)
        evt = AuditEvent(
            user_id=user.id,
            workspace_id=ws.id if ws else None,
            action=str(action)[:80],
            target=str(target or "")[:200],
            details=json.dumps(details or {}, default=str)[:4000],
            ip_address=(request.headers.get("X-Forwarded-For") or request.remote_addr or "")[:80]
        )
        db.session.add(evt)
        mdb = get_mongo_db()
        if mdb is not None:
            try:
                mdb.audit_events.insert_one({
                    "user_id": user.id,
                    "workspace_id": ws.id if ws else None,
                    "action": action,
                    "target": target,
                    "details": details or {},
                    "ip_address": evt.ip_address,
                    "created_at": datetime.datetime.utcnow()
                })
            except Exception:
                app.logger.exception("Mongo audit mirror failed")
    except Exception:
        app.logger.exception("Audit event failed")

def get_retention_policy(user):
    pol = RetentionPolicy.query.filter_by(user_id=user.id).first()
    if not pol:
        pol = RetentionPolicy(user_id=user.id, days=int(os.environ.get("DEFAULT_RETENTION_DAYS", "30")))
        db.session.add(pol)
        db.session.flush()
    return pol

def storage_status(user):
    user_dir = os.path.join(UPLOAD_DIR, str(user.id))
    total_bytes = 0
    file_count = 0
    if os.path.isdir(user_dir):
        for name in os.listdir(user_dir):
            path = os.path.join(user_dir, name)
            if os.path.isfile(path):
                file_count += 1
                total_bytes += os.path.getsize(path)
    sessions = LogSession.query.filter_by(user_id=user.id).count()
    return {
        "backend": "railway-volume",
        "path": UPLOAD_DIR,
        "stored_files": file_count,
        "bytes": total_bytes,
        "mb": round(total_bytes/1024/1024, 2),
        "sessions": sessions,
        "mongo_configured": bool(MONGO_URI),
        "max_upload_mb": app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024),
    }

def apply_retention_for_user(user):
    pol = get_retention_policy(user)
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=max(1, int(pol.days or 30)))
    old = LogSession.query.filter(LogSession.user_id == user.id, LogSession.created_at < cutoff).all()
    deleted = 0
    for item in old:
        delete_persisted_upload(user.id, item.id)
        db.session.delete(item)
        deleted += 1
    audit_event(user, "retention.apply", "LogSession", {"deleted_sessions": deleted, "days": pol.days})
    db.session.commit()
    return deleted


def retention_preview(user):
    pol = get_retention_policy(user)
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=max(1, int(pol.days or 30)))
    old = LogSession.query.filter(LogSession.user_id == user.id, LogSession.created_at < cutoff).all()
    keep = LogSession.query.filter(LogSession.user_id == user.id, LogSession.created_at >= cutoff).count()
    return {"retention_days": pol.days, "cutoff": cutoff.strftime("%Y-%m-%d %H:%M"), "would_delete": len(old), "surviving": keep}

def evaluate_alerts(user, log_session, result):
    """Evaluate active alert rules after ingestion; store firing history and email destinations."""
    fired = []
    for rule in AlertRule.query.filter_by(user_id=user.id, active=True).all():
        cond = (rule.condition or "").strip().lower()
        if cond in {"errors", "error", "error_count"}:
            value = float(result.get("errors", 0)); triggered = value > float(rule.threshold or 0)
        elif cond in {"warnings", "warns", "warn", "warning_count"}:
            value = float(result.get("warns", 0)); triggered = value > float(rule.threshold or 0)
        elif cond in {"latency", "p95", "p95_latency"}:
            value = float(result.get("p95", result.get("latency", 0))); triggered = value > float(rule.threshold or 0)
        elif cond in {"health", "health_score"}:
            value = float(result.get("health_score", 100)); triggered = value < float(rule.threshold or 0)
        elif cond in {"severity", "incident_severity"}:
            value = float((result.get("severity") or {}).get("score", 0)); triggered = value > float(rule.threshold or 0)
        else:
            continue
        if triggered:
            firing = AlertFiring(user_id=user.id, rule_id=rule.id, rule_name=rule.name or "Alert rule", condition=rule.condition or cond, value=value, threshold=float(rule.threshold or 0), session_id=log_session.id if log_session else 0, environment=(log_session.environment if log_session else result.get("environment", "")))
            db.session.add(firing)
            fired.append({"rule": firing.rule_name, "condition": firing.condition, "value": value, "threshold": firing.threshold})
    if fired:
        for dest in AlertDestination.query.filter_by(user_id=user.id, active=True).all():
            if dest.kind == "email" and dest.target:
                try:
                    msg = Message("ObserveX alert fired", recipients=[dest.target])
                    msg.body = "ObserveX alert(s) fired:\n" + "\n".join([f"- {x['rule']}: {x['condition']}={x['value']} threshold={x['threshold']}" for x in fired])
                    mail.send(msg)
                except Exception:
                    app.logger.exception("Alert notification failed")
        audit_event(user, "alert.fire", "ingestion", {"fired": fired})
    return fired


_db_init_lock = threading.Lock()

def init_db_once():
    with _db_init_lock:
        db.create_all()

with app.app_context():
    init_db_once()

@app.errorhandler(413)
def request_entity_too_large(error):
    if request.path.startswith("/analyse") or request.path.startswith("/api/"):
        return jsonify({"error": f"Uploaded log is too large. Current limit is {app.config['MAX_CONTENT_LENGTH'] // (1024 * 1024)} MB. Increase MAX_UPLOAD_MB in Railway or upload smaller files."}), 413
    return "Uploaded file too large", 413

@app.route("/health")
def health():
    try:
        db.session.execute(db.text("SELECT 1"))
        return jsonify({"status": "ok"}), 200
    except Exception as exc:
        app.logger.exception("Health check failed")
        return jsonify({"status": "error", "message": str(exc)}), 500

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    if request.path.startswith("/analyse") or request.path.startswith("/api/") or request.path in {"/alerts", "/history", "/profile/apikey", "/health"}:
        return jsonify({"error": "Internal server error. Please check Railway logs."}), 500
    return "Internal server error", 500

# ── Helpers ───────────────────────────────────────────────────────────────────
def get_current_user():
    """Return the logged-in user or clear a stale/invalid session."""
    uid = session.get("user_id")
    if not uid:
        return None
    user = db.session.get(User, uid)
    if user is None:
        session.clear()
    return user

DEFAULT_ENVIRONMENTS = ["PROD", "UAT", "SIT", "DEV", "PREPROD", "DR"]

PLAN_LIMITS = {
    "starter": {"storage_gb": 1, "ingestion_gb_month": 2, "users": 3, "retention_days": 7, "alerts": 3},
    "growth": {"storage_gb": 10, "ingestion_gb_month": 50, "users": 25, "retention_days": 30, "alerts": 25},
    "business": {"storage_gb": 100, "ingestion_gb_month": 500, "users": 100, "retention_days": 90, "alerts": 100},
    "enterprise": {"storage_gb": 1000, "ingestion_gb_month": 5000, "users": 1000, "retention_days": 365, "alerts": 1000},
}

def get_plan_limits(plan):
    return PLAN_LIMITS.get((plan or "starter").lower(), PLAN_LIMITS["starter"])

def schema_detection_sample(raw):
    low=(raw or "")[:20000].lower()
    if "muleruntime" in low or "loggermessageprocessor" in low: return "MuleSoft"
    if "cloudwatch" in low or "@timestamp" in low: return "AWS CloudWatch / JSON"
    if re.search(r'\b(GET|POST|PUT|DELETE)\s+/.*HTTP/', raw or ""): return "Nginx/Apache Access"
    if "exception in thread" in low or "java.lang" in low: return "Java"
    if "node.js" in low or "express" in low: return "Node.js"
    if (raw or "").lstrip().startswith(('{','[')): return "JSON"
    return "Generic text logs"

def incident_severity_score(result):
    total=max(1, int(result.get("total") or 0))
    error_rate=(int(result.get("errors") or 0)/total)*100
    warn_rate=(int(result.get("warns") or 0)/total)*100
    p95=int(result.get("p95") or 0)
    apps=len(result.get("apps") or [])
    impact=min(30, apps*5)
    score=min(100, round(error_rate*4 + warn_rate*1.5 + (25 if p95>3000 else 0) + impact))
    label="critical" if score>=75 else "high" if score>=50 else "medium" if score>=25 else "low"
    return {"score": score, "label": label, "why": [f"error rate {round(error_rate,2)}%", f"warn rate {round(warn_rate,2)}%", f"p95 latency {p95}ms", f"apps impacted {apps}"]}

def explain_rca(result):
    evidence=[]
    if result.get("top_errors"): evidence.append({"reason":"Repeated error cluster", "evidence": result["top_errors"][:3]})
    if result.get("hot_traces"): evidence.append({"reason":"Highest-signal trace/event", "evidence": result["hot_traces"][:2]})
    if result.get("dependencies"): evidence.append({"reason":"Dependency signals found in logs", "evidence": result["dependencies"][:5]})
    if result.get("timeline_buckets"): evidence.append({"reason":"Timeline buckets used for spike context", "evidence": result["timeline_buckets"][-5:]})
    return evidence or [{"reason":"No strong RCA evidence yet", "evidence":["Upload more logs or broaden date/search filters."]}]

def get_user_environments(user):
    custom = []
    if user is not None:
        custom = [e.name for e in CustomEnvironment.query.filter_by(user_id=user.id).order_by(CustomEnvironment.name.asc()).all()]
    envs = []
    for name in DEFAULT_ENVIRONMENTS + custom:
        clean = (name or "").strip().upper()
        if clean and clean not in envs:
            envs.append(clean)
    return envs

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if user is None:
            if request.path.startswith("/api/") or request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"error": "Session expired. Please login again."}), 401
            flash("Session expired. Please login again.", "info")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT


def percentile(values, pct):
    if not values:
        return 0
    values = sorted(values)
    k = (len(values)-1) * (pct/100)
    f = int(k)
    c = min(f+1, len(values)-1)
    if f == c:
        return values[f]
    return round(values[f] + (values[c]-values[f]) * (k-f))


def detect_level(line: str):
    if re.search(r"\b(DEBUG|TRACE)\b", line, re.I):
        return "DEBUG"
    if re.search(r"\b(SUCCESS|SUCCEEDED|COMPLETED|OK)\b|\b2\d\d\b", line, re.I):
        return "SUCCESS"
    if re.search(r"\b(FAIL|FAILED|FAILURE)\b", line, re.I):
        return "FAILURE"
    if re.search(r"\b(ERROR|FATAL|SEVERE)\b|exception|timeout|gateway timeout|bad request|\b5\d\d\b", line, re.I):
        return "ERROR"
    if re.search(r"\b(WARN|WARNING)\b|retry|slow|\b4\d\d\b", line, re.I):
        return "WARN"
    return "INFO"

def extract_first(patterns, text, default=""):
    for pat in patterns:
        m = re.search(pat, text, re.I | re.S)
        if m:
            return (m.group(1) or "").strip()
    return default

def uniq(seq, limit=200):
    out=[]; seen=set()
    for x in seq:
        if not x: continue
        x=str(x).strip().strip('"\'')
        if not x or x.lower() in seen: continue
        seen.add(x.lower()); out.append(x)
        if len(out)>=limit: break
    return out

def infer_environment(text: str, selected: str = "PROD"):
    selected = (selected or "PROD").upper()
    low = text.lower()
    for env in ["PROD", "UAT", "SIT", "DEV", "PREPROD", "DR", "SANDBOX"]:
        if re.search(rf"\b{env.lower()}\b|{env.lower()}[-_.]", low):
            return env
    if "hyderabad" in low or "hyd-dr" in low: return "DR"
    if "mumbai" in low and "prod" in low: return "PROD"
    return selected

def extract_apps(text: str):
    apps=[]
    apps += re.findall(r"\[([a-zA-Z][a-zA-Z0-9_-]*(?:api|API)[a-zA-Z0-9_-]*)\]", text)
    apps += re.findall(r'"ApplicationName"\s*:\s*"([^"\n]+)"', text, re.I)
    apps += re.findall(r"(?:app|application|service|applicationName)\s*[=:]\s*['\"]?([a-zA-Z0-9_.-]+)", text, re.I)
    apps += [m for m in re.findall(r"--- FILE:\s*([^\n]+?)\s*---", text) if "api" in m.lower()]
    cleaned=[]
    for a in apps:
        a=a.strip()
        a=re.sub(r"\.(log|txt|json)$", "", a, flags=re.I)
        a=re.sub(r"(-api)-\d+$", r"\1", a, flags=re.I)
        cleaned.append(a)
    return uniq(cleaned, 100)

def extract_trace_id(line: str):
    return extract_first([
        r"correlationId\"?\s*[:=]\s*\"?([a-zA-Z0-9-]{12,})",
        r"\bevent:\s*([a-zA-Z0-9-]{12,})",
        r"(?:traceId|trace|correlation-id|eventId|event-id)\s*[:=]\s*\"?([a-zA-Z0-9-]{8,})",
    ], line, "")

def extract_time(line: str, fallback: str = ""):
    return extract_first([
        r"(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:[,.]\d+)?)",
        r"(\d{2}:\d{2}:\d{2}(?:[,.]\d+)?)",
    ], line, fallback)

def parse_search_query(query: str):
    filters = {}
    if not query: return filters
    q = query.strip()
    for k, v in re.findall(r'(\w+):"([^"]+)"', q):
        filters[k.lower()] = v; q = q.replace(f'{k}:"{v}"', '')
    for k, op, v in re.findall(r'(latency|duration|timeTaken|avg)\s*([><=])\s*(\d+)', q, re.I):
        filters['latency_op'] = op; filters['latency_value'] = int(v)
    for k, v in re.findall(r'(env|environment|app|application|level|trace|traceid|event|eventid|flow|status|message|file|source|date)\s*:\s*([^\s]+)', q, re.I):
        filters[k.lower()] = v
    remaining = re.sub(r'\w+:"[^"]+"|\w+\s*:\s*[^\s]+|(latency|duration|timeTaken|avg)\s*[><=]\s*\d+', '', query, flags=re.I).strip()
    if remaining: filters['free'] = remaining
    return filters

LOG_HEADER_RE = re.compile(r"^(?:INFO|ERROR|WARN|WARNING|DEBUG|TRACE|FATAL|SUCCESS|FAILURE)\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[,.]\d{3}", re.I)

def group_multiline_log_records(raw: str, default_file: str = ""):
    records = []
    current = None
    current_file = default_file
    for idx, line in enumerate(raw.splitlines(), start=1):
        fm = re.search(r"--- FILE:\s*([^\n]+?)\s*---", line)
        if fm:
            if current:
                records.append(current)
                current = None
            current_file = fm.group(1).strip()
            continue
        if not line.strip():
            if current:
                current["message"].append(line)
            continue
        if LOG_HEADER_RE.search(line) or current is None:
            if current:
                records.append(current)
            current = {"line_no": idx, "file": current_file, "message": [line]}
        else:
            current["message"].append(line)
    if current:
        records.append(current)
    return records

def mask_secrets(text: str):
    """Mask common Indian PII, secrets, account identifiers and tokens before any UI/API response."""
    if not text:
        return text

    masked = str(text)

    # JWT and long bearer-like tokens
    masked = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "[MASKED_JWT]", masked)
    masked = re.sub(r"(?i)(authorization\s*[:=]\s*bearer\s+)[A-Za-z0-9._\-+/=]{16,}", r"\1[MASKED_TOKEN]", masked)
    masked = re.sub(r"(?i)(api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|bearer|token|password|passwd|pwd|secret|client[_-]?secret|signature|hmac)(\s*[=:]\s*['\"]?)([^\s,;\"'}]{4,})", r"\1\2[MASKED]", masked)

    # Aadhaar: 12 digits, with optional spaces/hyphens. Keep explicit masking conservative enough for logs.
    masked = re.sub(r"(?i)(aadhaar|aadhar|uidai)(\s*[=:]\s*['\"]?)(\d[ -]?){12}", r"\1\2[MASKED_AADHAAR]", masked)
    masked = re.sub(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}\b", "[MASKED_AADHAAR]", masked)

    # PAN card
    masked = re.sub(r"(?i)(pan|panNumber|pan_card)(\s*[=:]\s*['\"]?)[A-Z]{5}\d{4}[A-Z]", r"\1\2[MASKED_PAN]", masked)
    masked = re.sub(r"\b[A-Z]{5}\d{4}[A-Z]\b", "[MASKED_PAN]", masked)

    # Indian mobile numbers, including +91 / 91 prefixes
    masked = re.sub(r"(?i)(mobile|phone|customerMobile|contact|msisdn)(\s*[=:]\s*['\"]?)(?:\+?91[- ]?)?[6-9]\d{9}", r"\1\2[MASKED_MOBILE]", masked)
    masked = re.sub(r"(?<!\d)(?:\+?91[- ]?)?[6-9]\d{9}(?!\d)", "[MASKED_MOBILE]", masked)

    # Email addresses
    masked = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[MASKED_EMAIL]", masked)

    # Customer names and IDs found in JSON/log key-value pairs
    sensitive_keys = [
        "customerName", "name", "fullName", "firstName", "lastName",
        "loanNumber", "loanId", "accountNumber", "accountNo", "primaryCustomerId",
        "customerId", "applicationNo", "checkoutId", "bbpsId", "receiptNumber",
        "transactionId", "gatewayTransactionId", "upiId", "vpa", "cardNumber", "ifsc"
    ]
    key_alt = "|".join(map(re.escape, sensitive_keys))
    masked = re.sub(rf"(?i)(\"(?:{key_alt})\"\s*:\s*\")([^\"]+)(\")", r"\1[MASKED]\3", masked)
    masked = re.sub(rf"(?i)(\b(?:{key_alt})\b\s*[=:]\s*['\"]?)([A-Za-z0-9@._\- /]+)", r"\1[MASKED]", masked)

    # Long numeric identifiers likely to be account/loan/reference numbers.
    masked = re.sub(r"\b(?:TR|PP|BD|FS|GLB|APPL|APPT)[A-Z0-9]{6,}\b", "[MASKED_ID]", masked)

    return masked


def persist_raw_upload(user_id: int, session_id: int, filename: str, raw: str):
    """Persist a masked copy without slowing large uploads."""
    if SKIP_PERSIST_RAW:
        return None
    safe_name = secure_filename(filename or "upload.log")[:120]
    user_dir = os.path.join(UPLOAD_DIR, str(user_id))
    os.makedirs(user_dir, exist_ok=True)
    path = os.path.join(user_dir, f"session-{session_id}-{safe_name}.masked.log")
    text = raw if len(raw) <= MAX_PERSIST_CHARS else (raw[:MAX_PERSIST_CHARS] + "\n...[TRUNCATED_FOR_FAST_UPLOAD]...")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(mask_secrets(text))
    return path


def delete_persisted_upload(user_id: int, session_id: int):
    user_dir = os.path.join(UPLOAD_DIR, str(user_id))
    if not os.path.isdir(user_dir):
        return
    prefix = f"session-{session_id}-"
    for name in os.listdir(user_dir):
        if name.startswith(prefix):
            try:
                os.remove(os.path.join(user_dir, name))
            except OSError:
                pass

def build_log_rows(records, env, filename=""):
    rows=[]
    current_app=""; current_file=filename
    for rec in records:
        line = "\n".join(rec.get("message") or [])
        current_file = rec.get("file") or current_file
        app = extract_first([
            r"\[([a-zA-Z][a-zA-Z0-9_-]*(?:api|API)[a-zA-Z0-9_-]*)\]",
            r'"ApplicationName"\s*:\s*"([^"\n]+)"',
            r"(?:app|application|service|applicationName)\s*[=:]\s*['\"]?([a-zA-Z0-9_.-]+)"
        ], line, current_app or "unknown")
        if app != "unknown": current_app=app
        trace = extract_trace_id(line)
        status = extract_first([r'"HttpStatus"\s*:\s*(\d{3})', r"(?:status|statusCode|httpStatus)\s*[=:]\s*(\d{3})", r"\b(5\d\d|4\d\d|2\d\d)\b"], line, "")
        lat = extract_first([r"(?:latency|duration|timeTaken|elapsed)\s*[=: ]+([0-9]+)", r"completed in\s+([0-9]+)\s*ms"], line, "")
        if not lat:
            times = re.findall(r'"TimestampIST"\s*:\s*"([^"]+)"', line, re.I)
            if len(times) >= 2:
                try:
                    t1=datetime.datetime.fromisoformat(times[0].replace('Z',''))
                    t2=datetime.datetime.fromisoformat(times[-1].replace('Z',''))
                    lat = str(max(0, int((t2-t1).total_seconds()*1000)))
                except Exception:
                    lat = ""
        flow = extract_first([r"processor:\s*([^;\]]+)", r'"FlowName"\s*:\s*"([^"]+)"', r"\]\.([a-zA-Z0-9_-]+flow)\."], line, "")
        # Endpoint-aware extraction: dashboards should group by business API, not Mule /processors/N paths.
        api_method = extract_first([r"\]\.(get|post|put|patch|delete):", r"\b(GET|POST|PUT|PATCH|DELETE)\s+/"], line, "")
        api_path = extract_first([
            r"\]\.(?:get|post|put|patch|delete):\\([^:\]\s]+)",
            r"\]\.(?:get|post|put|patch|delete):(/[^:\]\s]+)",
            r'"RequestUri"\s*:\s*"([^"]+)"',
            r'\b(?:GET|POST|PUT|PATCH|DELETE)\s+(/[^\s"\']+)'
        ], line, "")
        if api_path:
            api_path = "/" + api_path.strip("/\\").replace("\\", "/")
        flow_group = re.sub(r"/processors.*$", "", flow or "", flags=re.I)
        rows.append({
            "line_no": rec.get("line_no"), "time": extract_time(line, f"line {rec.get('line_no')}"), "env": env,
            "file": current_file, "level": detect_level(line), "app": app, "trace": trace,
            "event": trace, "flow": flow, "flow_group": flow_group, "api": api_path, "method": api_method.upper() if api_method else "",
            "status": status, "latency": int(lat) if str(lat).isdigit() else 0,
            "message": mask_secrets(line), "is_multiline": "\n" in line
        })
    return rows

def row_matches_filters(row, filters):
    if not filters: return True
    hay = " ".join(str(v) for v in row.values()).lower()
    envf = (filters.get('env') or filters.get('environment'))
    if envf and envf.lower() != str(row.get('env','')).lower(): return False
    keymap = {'application':'app','traceid':'trace','eventid':'event','source':'file','date':'time'}
    for k,v in filters.items():
        if k in {'latency_op','latency_value','env','environment'}: continue
        col = keymap.get(k,k)
        if col in row:
            if str(v).lower() not in str(row.get(col,'')).lower(): return False
        elif k == 'free':
            for term in str(v).lower().split():
                if term not in hay: return False
    if 'latency_value' in filters:
        val=filters['latency_value']; lat=int(row.get('latency') or 0); op=filters.get('latency_op','>')
        if op == '>' and not lat > val: return False
        if op == '<' and not lat < val: return False
        if op == '=' and not lat == val: return False
    return True

def analyse_log_text(raw: str, query: str = "", env: str = "PROD", filename: str = ""):
    truncated_for_speed = False
    if MAX_ANALYSE_LINES > 0:
        raw_lines = raw.splitlines()
        if len(raw_lines) > MAX_ANALYSE_LINES:
            raw = "\n".join(raw_lines[-MAX_ANALYSE_LINES:])
            truncated_for_speed = True
    records = group_multiline_log_records(raw, filename)
    detected_env = infer_environment(raw[:5000], env)
    all_rows = build_log_rows(records, detected_env, filename)
    filters = parse_search_query(query)
    rows = [r for r in all_rows if row_matches_filters(r, filters)]
    lines = [r['message'] for r in rows]
    joined = "\n".join(lines)

    errors = [r for r in rows if r['level'] == 'ERROR']
    warns  = [r for r in rows if r['level'] == 'WARN']
    apps   = extract_apps(raw) or uniq([r['app'] for r in rows if r['app'] != 'unknown'])
    traces = uniq([r['trace'] for r in rows if r.get('trace')], 250)
    lats   = [r['latency'] for r in rows if r.get('latency')]
    json_latencies=[]
    for m in re.finditer(r'"TimestampIST"\s*:\s*"([^"]+)".*?"TimestampIST"\s*:\s*"([^"]+)"', raw, re.I|re.S):
        try:
            t1=datetime.datetime.fromisoformat(m.group(1).replace('Z',''))
            t2=datetime.datetime.fromisoformat(m.group(2).replace('Z',''))
            json_latencies.append(int((t2-t1).total_seconds()*1000))
        except Exception:
            pass
    if not lats and json_latencies: lats=json_latencies

    avg_lat = round(sum(lats)/len(lats)) if lats else 0
    p95 = percentile(lats, 95); p99 = percentile(lats, 99)
    total = len(rows)
    error_rate = round(len(errors)/total*100, 2) if total else 0
    warn_rate = round(len(warns)/total*100, 2) if total else 0
    app_counts={}
    for appn in apps:
        app_counts[appn]=sum(1 for r in rows if appn.lower() in (r.get('app','')+' '+r.get('message','')).lower())
    status_counts={}
    for r in rows:
        st=r.get('status')
        if st: status_counts[st]=status_counts.get(st,0)+1
    top_errors={}
    for r in errors:
        msg=r['message']
        key = extract_first([
            r"(?:Exception|ERROR|Error|failed|failure)[:\s]+([A-Za-z0-9_.:-]+)",
            r"(JWT|token|timeout|connection|bad request|gateway|unauthorized|forbidden|exception|failure)"
        ], msg, "General error")
        top_errors[key]=top_errors.get(key,0)+1
    top_errors=sorted(top_errors.items(), key=lambda x:x[1], reverse=True)[:10]
    dynamic_tags=set()
    # Build tags from the actual uploaded/ingested logs. No customer-specific hardcoding.
    for r in rows:
        msg=(r.get('message') or '').lower()
        flow=(r.get('flow') or '').lower()
        app=(r.get('app') or '').lower()
        if 'jwt' in msg or 'token' in msg: dynamic_tags.add('JWT / Token')
        if 'success' in msg or r.get('level') == 'SUCCESS' or str(r.get('status','')).startswith('2'): dynamic_tags.add('Success')
        if 'fail' in msg or r.get('level') in {'ERROR','FAILURE'}: dynamic_tags.add('Failure')
        if r.get('latency',0) > 3000 or 'timeout' in msg or 'slow' in msg: dynamic_tags.add('Slow API')
        for token in re.findall(r'\b(get|post|put|delete):\\?([a-zA-Z0-9_\-/]+)', r.get('message',''), re.I):
            path=token[1].strip('\\/')
            if path: dynamic_tags.add(path.split('/')[0].replace('-', ' ').title() + ' API')
        for word in re.findall(r'\b[A-Za-z][A-Za-z0-9_-]{2,}\b', flow + ' ' + app):
            wl=word.lower()
            if wl not in {'api','subflow','processors','processor','flow','config','cpu','lite','blocking','main','impl'} and len(word) > 3:
                dynamic_tags.add(word.replace('-', ' ').title())
    smart_tags=sorted(dynamic_tags)[:18]
    dep_candidates=[]
    dep_patterns=[
        r'before request to ([^\n*{]+)', r'after request to ([^\n*{]+)',
        r'before ([a-zA-Z0-9_. -]+?) call', r'after ([a-zA-Z0-9_. -]+?) call',
        r'processor:\s*([^;\]]+)', r'\bintermediaryId"?\s*:\s*"([^"]+)"',
        r'\bsourceModule"?\s*:\s*"([^"]+)"', r'\bcheckoutApp"?\s*:\s*"([^"]+)"'
    ]
    for pat in dep_patterns:
        dep_candidates += re.findall(pat, raw, re.I)
    deps=[]
    for d in dep_candidates:
        d=str(d).strip().strip('"').strip()
        d=re.sub(r'\s+log.*$','',d, flags=re.I)
        d=re.sub(r'/processors.*$','',d, flags=re.I)
        if d and len(d) <= 70 and not re.search(r'logger|muleruntime|runtime|processor$', d, re.I):
            deps.append(d)
    deps=uniq(deps, 20)
    findings = [
        {"label": f"{detected_env}: {len(errors)} error line(s), {len(warns)} warning line(s)", "type": "error" if errors else ("warn" if warns else "ok")},
        {"label": f"Applications detected: {', '.join(apps[:8]) or 'none'}", "type": "ok" if apps else "warn"},
        {"label": f"Avg {avg_lat}ms · P95 {p95}ms · P99 {p99}ms", "type": "warn" if p95 > 3000 else "info"},
        {"label": f"Trace/Event IDs found: {len(traces)}", "type": "info"},
    ]
    # Intelligence layer: turn raw logs into a problem-first debugging view.
    trace_counts={}
    for r in rows:
        tid=r.get('trace') or r.get('event')
        if tid:
            trace_counts.setdefault(tid, {"count":0,"errors":0,"latency":0,"app":r.get('app','unknown'),"sample":r.get('message','')})
            trace_counts[tid]["count"] += 1
            trace_counts[tid]["errors"] += 1 if r.get('level') == 'ERROR' else 0
            trace_counts[tid]["latency"] = max(trace_counts[tid]["latency"], int(r.get('latency') or 0))
    hot_traces=sorted([{ "trace":k, **v } for k,v in trace_counts.items()], key=lambda x:(x["errors"], x["latency"], x["count"]), reverse=True)[:8]

    by_app={}
    for r in rows:
        a=r.get('app') or 'unknown'
        by_app.setdefault(a,{"lines":0,"errors":0,"warns":0,"latencies":[]})
        by_app[a]["lines"]+=1
        by_app[a]["errors"]+=1 if r.get('level')=='ERROR' else 0
        by_app[a]["warns"]+=1 if r.get('level')=='WARN' else 0
        if r.get('latency'): by_app[a]["latencies"].append(r['latency'])
    app_health=[]
    for a,v in by_app.items():
        avg=round(sum(v['latencies'])/len(v['latencies'])) if v['latencies'] else 0
        severity='critical' if v['errors'] else ('warn' if v['warns'] or avg>3000 else 'ok')
        app_health.append({"app":a,"lines":v['lines'],"errors":v['errors'],"warns":v['warns'],"avg_latency":avg,"severity":severity})
    app_health=sorted(app_health, key=lambda x:(x['severity']!='critical', -x['errors'], -x['avg_latency']))[:12]

    time_buckets={}
    for r in rows:
        t=str(r.get('time') or '')[:16]
        if t:
            time_buckets.setdefault(t,{"total":0,"errors":0,"warns":0})
            time_buckets[t]['total']+=1
            time_buckets[t]['errors']+=1 if r.get('level')=='ERROR' else 0
            time_buckets[t]['warns']+=1 if r.get('level')=='WARN' else 0
    timeline_buckets=[{"time":k, **v} for k,v in sorted(time_buckets.items())[-30:]]

    suspected=[]
    if top_errors: suspected.append(f"Most repeated error cluster is '{top_errors[0][0]}' with {top_errors[0][1]} hits")
    if hot_traces and hot_traces[0]['errors']: suspected.append(f"Trace {hot_traces[0]['trace']} carries the highest failure signal")
    if deps and (errors or p95>3000): suspected.append("External dependency involvement detected: " + ", ".join(deps[:4]))
    if p95>3000: suspected.append(f"Latency hotspot detected: P95 {p95}ms")
    root_cause = suspected[0] if suspected else "No strong failure pattern detected in the current upload"

    suggestions=[]
    if errors: suggestions.append("Start with Guided Debugging: inspect the top failed trace and compare the 10 preceding log lines.")
    if top_errors: suggestions.append("Group similar errors and assign ownership by app/dependency instead of reading raw logs line by line.")
    if len(apps)>1: suggestions.append("Use application health cards to isolate one API before opening the raw log table.")
    if p95>3000: suggestions.append("Investigate dependency timeout/retry settings and slow external calls before scaling infrastructure.")
    if 'JWT / Token' in smart_tags: suggestions.append("JWT/token logs detected. Mask secrets before sharing screenshots or reports.")
    if not suggestions: suggestions.append("System looks stable. Save this upload as the baseline for deployment comparison.")
    score=max(0, min(100, 100 - min(50, error_rate*5) - min(25, warn_rate*2) - (15 if p95>3000 else 0)))
    action_cards=[
        {"title":"Investigate failing trace","value": hot_traces[0]['trace'] if hot_traces else "No trace yet", "type":"critical" if errors else "ok"},
        {"title":"Check top app", "value": app_health[0]['app'] if app_health else "Unknown", "type": app_health[0]['severity'] if app_health else "warn"},
        {"title":"Review dependency", "value": deps[0] if deps else "No dependency signal", "type":"warn" if deps else "ok"},
        {"title":"Deploy readiness", "value": f"Health {round(score)}/100", "type":"critical" if error_rate>5 else ("warn" if warn_rate>10 or p95>3000 else "ok")},
    ]
    deploy_summary={"errors_delta":"baseline needed","latency_delta":"baseline needed","health_score":round(score),"recommendation":"Block release until critical errors are explained." if errors and round(score)<70 else "Safe to continue with monitoring."}
    schema_type = schema_detection_sample(raw)
    severity = incident_severity_score({"total": total, "errors": len(errors), "warns": len(warns), "p95": p95, "apps": apps})
    rca_explain = explain_rca({"top_errors": top_errors, "hot_traces": hot_traces, "dependencies": deps, "timeline_buckets": timeline_buckets})
    return {
        "schema_type": schema_type, "severity": severity, "rca_explain": rca_explain,
        "environment": detected_env, "total": total, "original_total": len(all_rows), "physical_lines": len(raw.splitlines()), "errors": len(errors), "warns": len(warns),
        "latency": avg_lat, "p95": p95, "p99": p99, "error_rate": error_rate, "warn_rate": warn_rate,
        "apps": apps, "app_counts": app_counts, "traces": traces, "events": traces, "statuses": status_counts,
        "top_errors": top_errors, "findings": findings, "suggestions": suggestions, "smart_tags": smart_tags,
        "dependencies": deps, "health_score": round(score), "log_rows": rows[:2000],
        "root_cause": root_cause, "hot_traces": hot_traces, "app_health": app_health,
        "timeline_buckets": timeline_buckets, "action_cards": action_cards, "deploy_summary": deploy_summary,
        "preview": "\n".join(lines[:500]),
        "flow": "Client → " + " → ".join(apps[:5]) + (" → External Dependencies" if deps else "") if apps else "",
        "error_lines": [r['message'] for r in errors[:50]], "slow_lines": [r['message'] for r in rows if r.get('latency',0)>3000][:50],
        "timeline": rows[:500],
        "query_help": "Use env:PROD app:s-htmltopdf-api level:ERROR trace:<id> message:\"otp success\" latency>3000 date:2026-04-11",
        "truncated_for_speed": truncated_for_speed, "max_analyse_lines": MAX_ANALYSE_LINES
    }

def send_reset_email(user):
    token   = secrets.token_urlsafe(40)
    expires = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    user.reset_token   = token
    user.reset_expires = expires
    db.session.commit()
    link = url_for("reset_password", token=token, _external=True)
    try:
        msg = Message("ObserveX – Password Reset", recipients=[user.email])
        msg.body = f"Hi {user.name},\n\nReset your password:\n{link}\n\nExpires in 1 hour."
        mail.send(msg)
        return True
    except Exception:
        return False

# ── Auth routes ───────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("public.html", page="home")

@app.route("/features")
def public_features():
    return render_template("public.html", page="features")

@app.route("/pricing")
def public_pricing():
    return render_template("public.html", page="pricing")

@app.route("/security")
def public_security():
    return render_template("public.html", page="security")

@app.route("/product")
def public_product():
    return render_template("public.html", page="product")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        pwd   = request.form.get("password", "")
        user  = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, pwd):
            session["user_id"]   = user.id
            session["user_name"] = user.name
            return redirect(url_for("dashboard"))
        flash("Invalid email or password.", "error")
    return render_template("login.html")

@app.route("/login/google")
def google_login():
    if google is None:
        flash("Google login is not configured yet. Add GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in Railway variables.", "info")
        return redirect(url_for("login"))
    redirect_uri = os.environ.get("GOOGLE_REDIRECT_URI") or url_for("google_callback", _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route("/auth/google/callback")
def google_callback():
    if google is None:
        flash("Google login is not configured.", "error")
        return redirect(url_for("login"))
    token = google.authorize_access_token()
    info = token.get("userinfo") or google.parse_id_token(token)
    email = (info.get("email") or "").strip().lower()
    name = info.get("name") or email.split("@")[0]
    if not email:
        flash("Google did not return an email address.", "error")
        return redirect(url_for("login"))
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(name=name, email=email, password_hash=generate_password_hash(secrets.token_urlsafe(32)))
        db.session.add(user); db.session.flush()
        ws = Workspace(owner_id=user.id, name=f"{name}'s Workspace")
        db.session.add(ws); db.session.flush()
        db.session.add(WorkspaceMember(workspace_id=ws.id, user_id=user.id, role="Admin"))
        audit_event(user, "auth.google_signup", email, {})
        db.session.commit()
    session["user_id"] = user.id
    session["user_name"] = user.name
    audit_event(user, "auth.google_login", email, {})
    db.session.commit()
    return redirect(url_for("dashboard"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name  = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        pwd   = request.form.get("password", "")
        workspace_name = request.form.get("workspace_name", "").strip()
        invite_code = request.form.get("invite_code", "").strip()
        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "error")
        elif len(pwd) < 8:
            flash("Password must be at least 8 characters.", "error")
        else:
            user = User(name=name, email=email,
                        password_hash=generate_password_hash(pwd))
            db.session.add(user)
            db.session.flush()
            invite = InviteCode.query.filter_by(code=invite_code, active=True).first() if invite_code else None
            if invite:
                db.session.add(WorkspaceMember(workspace_id=invite.workspace_id, user_id=user.id, role=invite.role))
            else:
                ws = Workspace(owner_id=user.id, name=workspace_name or f"{name or 'My'} Workspace")
                db.session.add(ws); db.session.flush()
                db.session.add(WorkspaceMember(workspace_id=ws.id, user_id=user.id, role="Admin"))
            db.session.commit()
            session["user_id"]   = user.id
            session["user_name"] = user.name
            return redirect(url_for("dashboard"))
    return render_template("register.html")

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user  = User.query.filter_by(email=email).first()
        if user:
            ok = send_reset_email(user)
            flash("Reset link sent – check your inbox." if ok
                  else "Email sending failed. Configure MAIL_* env vars.", "info")
        else:
            flash("If that email exists, a reset link has been sent.", "info")
        return redirect(url_for("forgot_password"))
    return render_template("forgot_password.html")

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    if not user or user.reset_expires < datetime.datetime.utcnow():
        flash("Reset link is invalid or expired.", "error")
        return redirect(url_for("forgot_password"))
    if request.method == "POST":
        pwd = request.form.get("password", "")
        if len(pwd) < 8:
            flash("Password must be at least 8 characters.", "error")
        else:
            user.password_hash = generate_password_hash(pwd)
            user.reset_token   = None
            user.reset_expires = None
            db.session.commit()
            flash("Password updated – please log in.", "success")
            return redirect(url_for("login"))
    return render_template("reset_password.html", token=token)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ── Dashboard ─────────────────────────────────────────────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():
    return render_app_page("dashboard")

def render_app_page(active="dashboard"):
    user = get_current_user()
    recent = LogSession.query.filter_by(user_id=user.id).order_by(LogSession.created_at.desc()).limit(10).all()
    alerts = AlertRule.query.filter_by(user_id=user.id).all()
    ws = ensure_default_workspace(user)
    role = get_user_role(user)
    return render_template("dashboard.html", user=user, recent=recent, alerts=alerts, environments=get_user_environments(user), workspace=ws, role=role, limits=get_plan_limits(ws.plan if ws else "starter"), active_section=active)

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

# ── Log analysis ──────────────────────────────────────────────────────────────
@app.route("/analyse", methods=["POST"])
@login_required
def analyse():
    try:
        env = request.form.get("env", "PROD")
        query = request.form.get("query", "")
        raw_parts = []
        fname = "paste"
        fnames = []

        if "logfile" in request.files:
            files = request.files.getlist("logfile")
            for f in files:
                if not f or not f.filename:
                    continue
                if not allowed_file(f.filename):
                    return jsonify({"error": f"Unsupported file type: {f.filename}. Upload .log, .txt or .json only."}), 400
                fname = secure_filename(f.filename)
                fnames.append(fname)
                raw_parts.append(f"\n--- FILE: {fname} ---\n" + f.read().decode("utf-8", errors="replace"))

        raw = "".join(raw_parts)
        if fnames:
            fname = ", ".join(fnames[:6]) + ("..." if len(fnames) > 6 else "")
        if not raw and request.form.get("raw_paste"):
            raw = request.form["raw_paste"]
            fname = "paste"

        if not raw:
            return jsonify({"error": "No log content provided"}), 400

        start_ms = time.time()
        result = analyse_log_text(raw, query, env, fname)
        result["source_health"] = {"file_upload":"active", "api_ingestion":"available", "s3":"not_connected", "last_ingest":"now"}
        user = get_current_user()
        if user is None:
            return jsonify({"error": "Session expired. Please login again."}), 401
        ls = LogSession(user_id=user.id, environment=env, filename=fname,
                        total_lines=result["total"], error_count=result["errors"],
                        warn_count=result["warns"], avg_latency=result["latency"],
                        apps_found=",".join(result["apps"]))
        db.session.add(ls)
        db.session.commit()
        # Persist masked raw logs in the background so large uploads do not block the response.
        try:
            threading.Thread(target=persist_raw_upload, args=(user.id, ls.id, fname, raw), daemon=True).start()
        except Exception:
            app.logger.exception("Could not schedule upload persistence")
        duration_ms = int((time.time()-start_ms)*1000)
        db.session.add(QueryMetric(user_id=user.id, action="upload_analyse", duration_ms=duration_ms, rows=result.get("total",0), bytes=len(raw.encode("utf-8", errors="ignore"))))
        audit_event(user, "logs.upload", fname, {"session_id": ls.id, "environment": env, "total": result.get("total"), "errors": result.get("errors"), "duration_ms": duration_ms, "schema": result.get("schema_type")})
        try:
            result["alerts_fired"] = evaluate_alerts(user, ls, result)
        except Exception:
            app.logger.exception("Alert evaluation failed")
            result["alerts_fired"] = []
        db.session.commit()
        result["session_id"] = ls.id
        result["stored"] = True
        return jsonify(result)
    except Exception as exc:
        db.session.rollback()
        app.logger.exception("Log analysis failed")
        return jsonify({"error": f"Log analysis failed: {str(exc)}"}), 500

# ── API ingestion (Bearer auth) ───────────────────────────────────────────────
@app.route("/api/v1/logs/ingest", methods=["POST"])
def api_ingest():
    MAX_INGEST_BYTES = int(os.environ.get("MAX_INGEST_BYTES", 25 * 1024 * 1024))
    if request.content_length and request.content_length > MAX_INGEST_BYTES:
        return jsonify({"error": "Payload too large", "limitBytes": MAX_INGEST_BYTES}), 413
    remote_key = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0]
    if api_rate_limited(remote_key):
        return jsonify({"error": "Rate limit exceeded", "retryAfterSeconds": 60}), 429
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "Missing token. Use Authorization: Bearer <OBSERVEX_API_KEY>"}), 401
    key  = auth.split(" ", 1)[1]
    user = User.query.filter_by(api_key=key).first()
    if not user:
        return jsonify({"error": "Invalid API key"}), 401

    data  = request.get_json(force=True, silent=True) or {}
    env   = (data.get("environment") or "PROD").upper()
    app_n = data.get("application") or data.get("app") or "api-source"
    source = data.get("source", "api")

    raw = data.get("logs", "")
    # Supports both raw string logs and structured event objects.
    # Accepted structured payload:
    # { environment, eventId, application, timestamp, payload }
    # or { environment, application, logs:[{timestamp, level, eventId, message, payload}] }
    if isinstance(raw, list):
        rows = raw
    elif isinstance(raw, dict):
        rows = [raw]
    elif raw:
        rows = None
    elif any(k in data for k in ("eventId", "event_id", "timestamp", "payload", "message")):
        rows = [data]
    else:
        rows = None

    if rows is not None:
        lines=[]
        for item in rows:
            if not isinstance(item, dict):
                lines.append(str(item)); continue
            ts = item.get("timestamp") or item.get("time") or datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            level = (item.get("level") or detect_level(str(item.get("message") or item.get("payload") or ""))).upper()
            eid = item.get("eventId") or item.get("event_id") or item.get("traceId") or item.get("correlationId") or ""
            msg = item.get("message") or item.get("msg") or "structured log"
            payload = item.get("payload", "")
            if isinstance(payload, (dict, list)):
                payload_txt = json.dumps(payload, ensure_ascii=False, default=str)
            else:
                payload_txt = str(payload or "")
            lines.append(f"{level} {str(ts).replace('T',' ').replace('Z','')} [[APIIngestion]: [{app_n}].{source}] [processor: api-ingestion; event: {eid}] org.observex.ingest.Logger: {msg} {payload_txt}")
        raw = "\n".join(lines)

    if not raw:
        return jsonify({"error": "logs field or structured event payload required"}), 400

    started = time.time()
    result = analyse_log_text(str(raw), "", env, app_n)
    duration_ms = int((time.time() - started) * 1000)
    ls = LogSession(
        user_id    = user.id,
        environment= env,
        filename   = app_n,
        total_lines= result["total"],
        error_count= result["errors"],
        warn_count = result["warns"],
        avg_latency= result["latency"],
        apps_found = ",".join(result["apps"]),
    )
    db.session.add(ls)
    db.session.flush()
    try:
        persist_raw_upload(user.id, ls.id, app_n, str(raw))
    except Exception:
        app.logger.exception("Could not persist API ingestion to volume")
    db.session.add(QueryMetric(user_id=user.id, action="api_ingest", duration_ms=duration_ms, rows=result.get("total",0), bytes=len(str(raw).encode("utf-8"))))
    audit_event(user, "logs.api_ingest", app_n, {"session_id": ls.id, "environment": env, "source": source, "total": result.get("total"), "errors": result.get("errors")})
    try:
        result["alerts_fired"] = evaluate_alerts(user, ls, result)
    except Exception:
        app.logger.exception("Alert evaluation failed")
        result["alerts_fired"] = []
    db.session.commit()
    return jsonify({
        "status": "success",
        "message": "Logs ingested and indexed",
        "session_id": ls.id,
        "environment": env,
        "application": app_n,
        "source": source,
        "ingested": result.get("total", 0),
        "processingTimeMs": duration_ms,
        "stored": True,
        "schema": result.get("schema", schema_detection_sample(str(raw))),
        "result": result
    })

@app.route("/api/v1/logs/ingest", methods=["GET"])
def api_ingest_docs_short():
    return jsonify({
        "endpoint": "POST /api/v1/logs/ingest",
        "auth": "Authorization: Bearer <OBSERVEX_API_KEY>",
        "raw_example": {"environment":"SANDBOX","application":"demo-checkout-api","logs":"INFO 2026-05-12 09:18:44 checkout completed"},
        "structured_example": {"environment":"SANDBOX","eventId":"demo-trace-8f91a2c4","application":"demo-checkout-api","timestamp":"2026-05-12 09:18:44","payload":{"status":"Success","orderId":"ORD-DEMO-1024","amount":2499}},
        "batch_example": {"environment":"SANDBOX","application":"demo-checkout-api","logs":[{"timestamp":"2026-05-12T09:18:44Z","level":"INFO","eventId":"demo-trace-8f91a2c4","message":"checkout completed","payload":{"status":"Success"}}]}
    })

# ── Alert rules ───────────────────────────────────────────────────────────────
@app.route("/alerts", methods=["GET", "POST", "DELETE"])
@login_required
def alerts():
    user = get_current_user()
    if user is None:
        return jsonify({"error": "Session expired. Please login again."}), 401
    uid = user.id
    if request.method == "POST":
        data = request.get_json(force=True)
        rule = AlertRule(user_id=uid, name=data["name"],
                         condition=data["condition"], threshold=data["threshold"])
        db.session.add(rule)
        db.session.commit()
        return jsonify({"id": rule.id, "name": rule.name})
    if request.method == "DELETE":
        rid  = request.args.get("id")
        rule = AlertRule.query.filter_by(id=rid, user_id=uid).first()
        if rule:
            db.session.delete(rule)
            db.session.commit()
        return jsonify({"status": "deleted"})
    rules = AlertRule.query.filter_by(user_id=uid).all()
    return jsonify([{"id": r.id, "name": r.name, "condition": r.condition,
                     "threshold": r.threshold, "active": r.active} for r in rules])

# ── History ───────────────────────────────────────────────────────────────────
@app.route("/history", methods=["GET", "DELETE"])
@login_required
def history():
    user = get_current_user()
    if user is None:
        return jsonify({"error": "Session expired. Please login again."}), 401
    uid = user.id
    if request.method == 'DELETE':
        sid = request.args.get('id')
        q = LogSession.query.filter_by(user_id=uid)
        if sid:
            item = q.filter_by(id=sid).first()
            if item:
                delete_persisted_upload(uid, item.id)
                db.session.delete(item)
        else:
            for item in q.all():
                delete_persisted_upload(uid, item.id)
                db.session.delete(item)
        audit_event(user, 'logs.delete', sid or 'all', {'scope':'history_delete'})
        db.session.commit()
        return jsonify({'status':'deleted'})
    sessions = LogSession.query.filter_by(user_id=uid)\
                               .order_by(LogSession.created_at.desc()).limit(50).all()
    return jsonify([{
        "id": s.id, "env": s.environment, "file": s.filename,
        "total": s.total_lines, "errors": s.error_count,
        "warns": s.warn_count, "latency": s.avg_latency,
        "apps": s.apps_found, "at": s.created_at.strftime("%Y-%m-%d %H:%M")
    } for s in sessions])

@app.route("/export/csv", methods=["POST"])
@login_required
def export_csv():
    data = request.get_json(force=True, silent=True) or {}
    rows = data.get("rows", [])
    output = "time,level,app,trace,event,latency,message\n"
    def clean(v):
        return '"' + str(v).replace('"','""').replace('\n',' ') + '"'
    for r in rows:
        output += ",".join(clean(r.get(k, "")) for k in ["time","level","app","trace","event","latency","message"]) + "\n"
    resp = make_response(output)
    resp.headers["Content-Type"] = "text/csv"
    resp.headers["Content-Disposition"] = "attachment; filename=observex-log-export.csv"
    audit_event(get_current_user(), "logs.export_csv", "visible_rows", {"rows": len(rows)})
    db.session.commit()
    return resp

@app.route("/assistant/suggest", methods=["POST"])
@login_required
def assistant_suggest():
    data = request.get_json(force=True, silent=True) or {}
    q = (data.get("question") or "").lower()
    result = data.get("result") or {}
    answer = []
    if "why" in q or "error" in q:
        top = result.get("top_errors") or []
        if top:
            answer.append("Top suspected error clusters: " + ", ".join([f"{k} ({v})" for k, v in top[:5]]))
        answer.append(f"Current filter has {result.get('errors', 0)} errors and {result.get('warns', 0)} warnings.")
    if "slow" in q or "latency" in q:
        answer.append(f"Latency summary: avg {result.get('latency',0)}ms, P95 {result.get('p95',0)}ms, P99 {result.get('p99',0)}ms.")
    if "prod" in q or "uat" in q or "compare" in q:
        answer.append("Use the Environment dropdown and the same search query to compare PROD/UAT/DEV sessions.")
    if not answer:
        answer.append("Try searches like level:ERROR, latency>3000, message:\"JWT token\", trace:<id>, or app:<api-name>.")
    return jsonify({"answer": " ".join(answer), "next_steps": result.get("suggestions", [])[:3]})

# ── Custom environments ──────────────────────────────────────────────────────
@app.route("/settings/environments", methods=["GET", "POST", "DELETE"])
@login_required
def settings_environments():
    user = get_current_user()
    if user is None:
        return jsonify({"error": "Session expired. Please login again."}), 401
    if request.method == "POST":
        if get_user_role(user) != "Admin":
            return jsonify({"error":"Only Admin can manage environments"}), 403
        data = request.get_json(force=True, silent=True) or {}
        name = re.sub(r"[^A-Za-z0-9_-]", "", (data.get("name") or "").upper())[:40]
        if not name:
            return jsonify({"error": "Environment name is required"}), 400
        existing = CustomEnvironment.query.filter_by(user_id=user.id, name=name).first()
        if not existing and name not in DEFAULT_ENVIRONMENTS:
            db.session.add(CustomEnvironment(user_id=user.id, name=name))
            db.session.commit()
        return jsonify({"environments": get_user_environments(user)})
    if request.method == "DELETE":
        if get_user_role(user) != "Admin":
            return jsonify({"error":"Only Admin can manage environments"}), 403
        name = re.sub(r"[^A-Za-z0-9_-]", "", (request.args.get("name") or "").upper())[:40]
        env = CustomEnvironment.query.filter_by(user_id=user.id, name=name).first()
        if env:
            db.session.delete(env)
            db.session.commit()
        return jsonify({"environments": get_user_environments(user)})
    return jsonify({"environments": get_user_environments(user), "defaults": DEFAULT_ENVIRONMENTS})


@app.route("/settings/saas", methods=["GET", "POST"])
@login_required
def settings_saas():
    user = get_current_user()
    ws = ensure_default_workspace(user)
    pol = get_retention_policy(user)
    if request.method == "POST":
        if get_user_role(user) != "Admin":
            return jsonify({"error":"Only Admin can update workspace SaaS settings"}), 403
        data = request.get_json(force=True, silent=True) or {}
        if data.get("workspace_name"):
            ws.name = str(data.get("workspace_name"))[:120]
        if data.get("plan"):
            ws.plan = str(data.get("plan"))[:40]
        if data.get("retention_days") is not None:
            pol.days = max(1, min(3650, int(data.get("retention_days") or 30)))
        pol.masked_only = bool(data.get("masked_only", True))
        pol.encrypted_raw_logs = bool(data.get("encrypted_raw_logs", False))
        pol.updated_at = datetime.datetime.utcnow()
        audit_event(user, "settings.saas_update", ws.name, {"retention_days": pol.days, "masked_only": pol.masked_only})
        db.session.commit()
    members = WorkspaceMember.query.filter_by(workspace_id=ws.id).all()
    return jsonify({
        "workspace": {"id": ws.id, "name": ws.name, "plan": ws.plan},
        "role": get_user_role(user),
        "members": [{"user_id": m.user_id, "role": m.role} for m in members],
        "retention": {"days": pol.days, "masked_only": pol.masked_only, "encrypted_raw_logs": pol.encrypted_raw_logs},
        "storage": storage_status(user),
        "recommendation": "Railway volume is fine for MVP. Use MongoDB Atlas for metadata/audit/search-light workloads. For heavy log search at scale, later add ClickHouse or OpenSearch."
    })

@app.route("/audit", methods=["GET"])
@login_required
def audit_events():
    user = get_current_user()
    rows = AuditEvent.query.filter_by(user_id=user.id).order_by(AuditEvent.created_at.desc()).limit(100).all()
    return jsonify([{
        "id": r.id, "action": r.action, "target": r.target, "details": json.loads(r.details or "{}"),
        "ip": r.ip_address, "at": r.created_at.strftime("%Y-%m-%d %H:%M:%S")
    } for r in rows])

@app.route("/retention/apply", methods=["POST"])
@login_required
def retention_apply():
    user = get_current_user()
    deleted = apply_retention_for_user(user)
    return jsonify({"status":"ok", "deleted_sessions": deleted})

@app.route("/retention/status", methods=["GET"])
@login_required
def retention_status():
    return jsonify(retention_preview(get_current_user()))

@app.route("/alert-firings", methods=["GET"])
@login_required
def alert_firings():
    user = get_current_user()
    rows = AlertFiring.query.filter_by(user_id=user.id).order_by(AlertFiring.fired_at.desc()).limit(100).all()
    return jsonify([{"id": r.id, "rule_id": r.rule_id, "rule_name": r.rule_name, "condition": r.condition, "value": r.value, "threshold": r.threshold, "session_id": r.session_id, "environment": r.environment, "notified": r.notified, "fired_at": r.fired_at.strftime("%Y-%m-%d %H:%M:%S")} for r in rows])

@app.route("/activity/summary", methods=["GET"])
@login_required
def activity_summary():
    user = get_current_user(); ws = ensure_default_workspace(user)
    out = []
    for m in WorkspaceMember.query.filter_by(workspace_id=ws.id).all():
        u = db.session.get(User, m.user_id)
        count = AuditEvent.query.filter_by(user_id=m.user_id).count()
        last = AuditEvent.query.filter_by(user_id=m.user_id).order_by(AuditEvent.created_at.desc()).first()
        out.append({"user_id": m.user_id, "name": u.name if u else "Unknown", "email": u.email if u else "", "role": m.role, "events": count, "last_activity": last.created_at.strftime("%Y-%m-%d %H:%M:%S") if last else None})
    return jsonify(out)

@app.route("/api-keys", methods=["GET"])
@login_required
def api_keys_status():
    user = get_current_user()
    return jsonify({"key_preview": "obsx_live_" + (user.api_key[-8:] if user.api_key else "not-set"), "created_for": user.email, "rotation_endpoint": "/profile/apikey", "docs": "/api/docs"})

@app.route("/usage", methods=["GET"])
@login_required
def usage():
    return jsonify(storage_status(get_current_user()))

@app.route("/connectors", methods=["GET", "POST", "DELETE"])
@login_required
def connectors():
    user = get_current_user()
    if request.method == "POST":
        data = request.get_json(force=True, silent=True) or {}
        c = SourceConnector(
            user_id=user.id,
            kind=str(data.get("kind") or "webhook")[:40],
            name=str(data.get("name") or "Connector")[:120],
            config_json=json.dumps(data.get("config") or {})[:4000],
        )
        db.session.add(c)
        audit_event(user, "connector.create", c.name, {"kind": c.kind})
        db.session.commit()
        return jsonify({"id": c.id, "status":"created"})
    if request.method == "DELETE":
        cid = request.args.get("id")
        c = SourceConnector.query.filter_by(user_id=user.id, id=cid).first()
        if c:
            audit_event(user, "connector.delete", c.name, {"kind": c.kind})
            db.session.delete(c)
            db.session.commit()
        return jsonify({"status":"deleted"})
    rows = SourceConnector.query.filter_by(user_id=user.id).order_by(SourceConnector.created_at.desc()).all()
    return jsonify([{
        "id": c.id, "kind": c.kind, "name": c.name, "active": c.active,
        "config": json.loads(c.config_json or "{}"), "at": c.created_at.strftime("%Y-%m-%d %H:%M")
    } for c in rows])

@app.route("/alert-destinations", methods=["GET", "POST", "DELETE"])
@login_required
def alert_destinations():
    user = get_current_user()
    if request.method == "POST":
        data = request.get_json(force=True, silent=True) or {}
        d = AlertDestination(user_id=user.id, kind=str(data.get("kind") or "email")[:30], target=str(data.get("target") or "")[:300])
        if not d.target:
            return jsonify({"error":"target is required"}), 400
        db.session.add(d)
        audit_event(user, "alert_destination.create", d.target, {"kind": d.kind})
        db.session.commit()
        return jsonify({"id": d.id, "status":"created"})
    if request.method == "DELETE":
        did = request.args.get("id")
        d = AlertDestination.query.filter_by(user_id=user.id, id=did).first()
        if d:
            audit_event(user, "alert_destination.delete", d.target, {"kind": d.kind})
            db.session.delete(d)
            db.session.commit()
        return jsonify({"status":"deleted"})
    rows = AlertDestination.query.filter_by(user_id=user.id).order_by(AlertDestination.created_at.desc()).all()
    return jsonify([{"id": d.id, "kind": d.kind, "target": d.target, "active": d.active, "at": d.created_at.strftime("%Y-%m-%d %H:%M")} for d in rows])

@app.route("/api/v1/logs/search", methods=["GET"])
def api_logs_search():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error":"Missing token"}), 401
    user = User.query.filter_by(api_key=auth.split(" ",1)[1]).first()
    if not user:
        return jsonify({"error":"Invalid API key"}), 401
    q = request.args.get("q", "")
    env = request.args.get("environment", "PROD")
    limit = min(1000, int(request.args.get("limit", "200") or 200))
    user_dir = os.path.join(UPLOAD_DIR, str(user.id))
    raw = ""
    if os.path.isdir(user_dir):
        for name in sorted(os.listdir(user_dir))[-10:]:
            if name.endswith(".masked.log"):
                try:
                    raw += f"\n--- FILE: {name} ---\n" + open(os.path.join(user_dir, name), encoding="utf-8", errors="replace").read()
                except Exception:
                    pass
    result = analyse_log_text(raw, q, env, "api-search") if raw else {"log_rows": [], "total": 0}
    audit_event(user, "logs.api_search", q, {"limit": limit})
    db.session.commit()
    return jsonify({"total": result.get("total",0), "rows": result.get("log_rows",[])[:limit]})

@app.route("/api/v1/trace/<trace_id>", methods=["GET"])
def api_trace_lookup(trace_id):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error":"Missing token"}), 401
    user = User.query.filter_by(api_key=auth.split(" ",1)[1]).first()
    if not user:
        return jsonify({"error":"Invalid API key"}), 401
    user_dir = os.path.join(UPLOAD_DIR, str(user.id))
    raw = ""
    if os.path.isdir(user_dir):
        for name in sorted(os.listdir(user_dir))[-10:]:
            if name.endswith(".masked.log"):
                try:
                    raw += f"\n--- FILE: {name} ---\n" + open(os.path.join(user_dir, name), encoding="utf-8", errors="replace").read()
                except Exception:
                    pass
    rows = []
    if raw:
        result = analyse_log_text(raw, f"trace:{trace_id}", request.args.get("environment", "PROD"), "api-trace")
        rows = result.get("log_rows", [])
    audit_event(user, "trace.lookup", trace_id, {"rows": len(rows)})
    db.session.commit()
    return jsonify({"trace_id": trace_id, "rows": rows})


@app.route("/api/docs")
def api_docs_page():
    return render_template("api_docs.html")

@app.route("/api/docs.json")
@login_required
def api_docs():
    user = get_current_user()
    return jsonify({
        "auth": "Authorization: Bearer <api_key>",
        "base_url": request.host_url.rstrip("/"),
        "storage_options": {
            "current": "Railway Volume + SQLite metadata",
            "railway_basic_recommendation": "Use Railway volume for masked raw files and SQLite for MVP metadata. Use MongoDB Atlas free/shared tier for audit events and searchable metadata if you cannot use Postgres yet.",
            "mongodb": {"env": ["MONGO_URI", "MONGO_DB_NAME"], "best_for": "audit events, connector configs, investigation documents, lightweight metadata", "not_best_for": "very large full-text log search at enterprise scale"},
            "future_scale": "S3/object storage for raw logs + Postgres metadata + ClickHouse/OpenSearch for high-speed search"
        },
        "endpoints": {
            "ingest": {
                "method": "POST", "path": "/api/v1/logs/ingest",
                "raw_request": {"environment":"SANDBOX", "application":"demo-checkout-api", "logs":"INFO 2026-05-12 09:18:44 checkout completed"},
                "structured_request": {"environment":"SANDBOX", "eventId":"demo-trace-8f91a2c4", "application":"demo-checkout-api", "timestamp":"2026-05-12 09:18:44", "payload": {"status":"Success", "orderId":"ORD-DEMO-1024", "amount": 2499}},
                "batch_request": {"environment":"SANDBOX", "application":"demo-checkout-api", "logs":[{"timestamp":"2026-05-12T09:18:44Z", "level":"INFO", "eventId":"demo-trace-8f91a2c4", "message":"checkout completed", "payload":{"status":"Success"}}]},
                "success_response": {"status":"success", "session_id":123, "stored": True, "ingested": 1, "processingTimeMs": 42},
                "failure_responses": {"401":"Missing/invalid API key", "400":"logs field or structured event payload required", "413":"payload exceeds MAX_UPLOAD_MB"}
            },
            "search": {"method":"GET", "path":"/api/v1/logs/search?q=env:SANDBOX app:demo-checkout-api level:ERROR&limit=200", "purpose":"Search recently persisted masked logs"},
            "trace": {"method":"GET", "path":"/api/v1/trace/<trace_id>", "purpose":"Return grouped trace/event timeline from persisted masked logs"},
            "connectors": {"method":"GET/POST/DELETE", "path":"/connectors", "types":["s3","cloudwatch","mulesoft","kafka","webhook"]},
            "alert_destinations": {"method":"GET/POST/DELETE", "path":"/alert-destinations", "types":["email","slack","teams","webhook"]},
            "audit": {"method":"GET", "path":"/audit"},
            "retention": {"method":"POST", "path":"/retention/apply"}
        },
        "security": [
            "JWT, bearer tokens, API keys, Aadhaar, PAN, mobile, email, customer names and loan/account/checkout identifiers are masked before UI/export/storage.",
            "Audit logs track upload, delete, export, connector, settings and trace lookup actions.",
            "Retention policy can auto-remove old sessions and volume files."
        ]
    })



@app.route("/api/docs/download")
def api_docs_download():
    content = """# ObserveX API Ingestion Guide

Base URL: https://your-domain.com

## Endpoint
POST /api/v1/logs/ingest
Authorization: Bearer obsx_demo_sk_live_xxxxx
Content-Type: application/json

## Raw log ingestion
```json
{
  "environment": "SANDBOX",
  "application": "demo-checkout-api",
  "source": "api",
  "logs": "INFO 2026-05-12 09:18:44 checkout completed"
}
```

## OR Structured event ingestion
```json
{
  "environment": "SANDBOX",
  "eventId": "demo-trace-8f91a2c4",
  "application": "demo-checkout-api",
  "timestamp": "2026-05-12 09:18:44",
  "payload": {
    "status": "Success",
    "orderId": "ORD-DEMO-1024",
    "amount": 2499
  }
}
```

## What ObserveX does automatically
- Schema detected: API/JSON
- PII masked: tokens, phone, email, PAN, Aadhaar
- Trace timeline created
- RCA evidence prepared

## API security checklist
- Use HTTPS only
- Rotate API keys regularly
- Keep keys outside frontend code
- Send only masked/sanitized payloads when possible
- Use 413/429 responses to backoff retry queues

## Responses
200 success, 400 invalid payload, 401 missing/invalid token, 413 too large, 500 server error.
"""
    resp = make_response(content)
    resp.headers["Content-Type"] = "text/markdown"
    resp.headers["Content-Disposition"] = "attachment; filename=observex-api-guide.md"
    return resp

@app.route("/demo/load", methods=["POST"])
@login_required
def demo_load():
    sample = r"""INFO 2026-04-27 10:00:00,100 [[MuleRuntime].uber.1: [demo-checkout-api].post:\checkout:application\json:demo-config.CPU_LITE] [processor: checkout-flow/processors/1; event: demo-trace-001] org.mule.runtime.core.internal.processor.LoggerMessageProcessor: before checkout log {"amount":2499,"checkoutStatus":"Success","customerMobile":"9876543210","orderReference":"ORD-DEMO-12345"}
ERROR 2026-04-27 10:00:03,450 [[MuleRuntime].uber.2: [demo-checkout-api].post:\checkout:application\json:demo-config.CPU_LITE] [processor: checkout-flow/processors/3; event: demo-trace-001] org.mule.runtime.core.internal.processor.LoggerMessageProcessor: downstream timeout while calling inventory service duration=3350
WARN 2026-04-27 10:01:04,450 [[MuleRuntime].uber.3: [demo-notification-api].post:\notify:application\json:demo-config.CPU_LITE] [processor: notify-flow/processors/2; event: demo-trace-002] org.mule.runtime.core.internal.processor.LoggerMessageProcessor: retry started for webhook call duration=1200
INFO 2026-04-27 10:01:06,150 [[MuleRuntime].uber.4: [demo-notification-api].post:\notify:application\json:demo-config.CPU_LITE] [processor: notify-flow/processors/4; event: demo-trace-002] org.mule.runtime.core.internal.processor.LoggerMessageProcessor: completed in 1700ms status=200
"""
    result = analyse_log_text(sample, "", "DEMO", "demo-incident.log")
    result["demo"] = True
    return jsonify(result)

@app.route("/onboarding/status")
@login_required
def onboarding_status():
    user=get_current_user(); ws=ensure_default_workspace(user)
    sessions=LogSession.query.filter_by(user_id=user.id).count()
    connectors_count=SourceConnector.query.filter_by(user_id=user.id).count()
    return jsonify({
        "steps":[
            {"name":"Create workspace", "done": bool(ws)},
            {"name":"Upload logs or load demo", "done": sessions>0},
            {"name":"Create API key", "done": bool(user.api_key)},
            {"name":"Connect source", "done": connectors_count>0},
            {"name":"Add alert destination", "done": AlertDestination.query.filter_by(user_id=user.id).count()>0},
        ]
    })

@app.route("/data-source-health")
@login_required
def data_source_health():
    user=get_current_user()
    latest=LogSession.query.filter_by(user_id=user.id).order_by(LogSession.created_at.desc()).first()
    connectors=SourceConnector.query.filter_by(user_id=user.id).all()
    return jsonify({
        "file_upload": {"status":"active" if latest else "waiting", "last_seen": latest.created_at.strftime("%Y-%m-%d %H:%M") if latest else None},
        "api_ingestion": {"status":"ready", "endpoint":"/api/v1/logs/ingest"},
        "s3": {"status":"active" if any(c.kind=='s3' and c.active for c in connectors) else "not_connected"},
        "connectors": [{"name":c.name,"kind":c.kind,"status":"active" if c.active else "disabled"} for c in connectors]
    })

@app.route("/performance")
@login_required
def performance():
    user=get_current_user()
    rows=QueryMetric.query.filter_by(user_id=user.id).order_by(QueryMetric.created_at.desc()).limit(100).all()
    return jsonify({"metrics":[{"action":r.action,"duration_ms":r.duration_ms,"rows":r.rows,"bytes":r.bytes,"at":r.created_at.strftime("%Y-%m-%d %H:%M:%S")} for r in rows]})

@app.route("/limits")
@login_required
def limits():
    user=get_current_user(); ws=ensure_default_workspace(user); st=storage_status(user); lim=get_plan_limits(ws.plan)
    return jsonify({"plan": ws.plan, "limits": lim, "usage": st})

@app.route("/workspace/invites", methods=["GET","POST","DELETE"])
@login_required
def workspace_invites():
    user=get_current_user(); ws=ensure_default_workspace(user)
    if get_user_role(user)!="Admin": return jsonify({"error":"Only Admin can manage invites"}),403
    if request.method=="POST":
        data=request.get_json(force=True, silent=True) or {}; role=data.get("role","Developer")
        if role not in {"Admin","Developer","Viewer","Auditor"}: role="Developer"
        inv=InviteCode(workspace_id=ws.id, code=secrets.token_urlsafe(12), role=role, created_by=user.id)
        db.session.add(inv); audit_event(user,"invite.create",role,{"code":inv.code}); db.session.commit()
        return jsonify({"code":inv.code,"role":inv.role})
    if request.method=="DELETE":
        code=request.args.get("code"); inv=InviteCode.query.filter_by(workspace_id=ws.id, code=code).first()
        if inv: inv.active=False; audit_event(user,"invite.disable",code,{}); db.session.commit()
        return jsonify({"status":"disabled"})
    invs=InviteCode.query.filter_by(workspace_id=ws.id).order_by(InviteCode.created_at.desc()).all()
    return jsonify([{"code":i.code,"role":i.role,"active":i.active,"at":i.created_at.strftime("%Y-%m-%d %H:%M")} for i in invs])

@app.route("/workspace/members", methods=["GET","POST","DELETE"])
@login_required
def workspace_members():
    user=get_current_user(); ws=ensure_default_workspace(user)
    if request.method!="GET" and get_user_role(user)!="Admin": return jsonify({"error":"Only Admin can manage members"}),403
    if request.method=="POST":
        data=request.get_json(force=True, silent=True) or {}; uid=int(data.get("user_id") or 0); role=data.get("role","Viewer")
        m=WorkspaceMember.query.filter_by(workspace_id=ws.id,user_id=uid).first()
        if m and role in {"Admin","Developer","Viewer","Auditor"}: m.role=role; audit_event(user,"member.role_update",uid,{"role":role}); db.session.commit()
        return jsonify({"status":"updated"})
    if request.method=="DELETE":
        uid=int(request.args.get("user_id") or 0); m=WorkspaceMember.query.filter_by(workspace_id=ws.id,user_id=uid).first()
        if m and uid!=ws.owner_id: db.session.delete(m); audit_event(user,"member.remove",uid,{}); db.session.commit()
        return jsonify({"status":"removed"})
    members=WorkspaceMember.query.filter_by(workspace_id=ws.id).all()
    out=[]
    for m in members:
        u=db.session.get(User,m.user_id); out.append({"user_id":m.user_id,"name":u.name if u else "Unknown","email":u.email if u else "", "role":m.role})
    return jsonify(out)

@app.route("/reports/share", methods=["POST"])
@login_required
def share_report():
    user=get_current_user(); data=request.get_json(force=True, silent=True) or {}
    token=secrets.token_urlsafe(24)
    rep=SharedReport(user_id=user.id, token=token, title=str(data.get("title") or "ObserveX RCA Report")[:180], content=mask_secrets(str(data.get("content") or ""))[:200000], expires_at=datetime.datetime.utcnow()+datetime.timedelta(days=int(data.get("days") or 7)))
    db.session.add(rep); audit_event(user,"report.share",rep.title,{"expires_at":rep.expires_at}); db.session.commit()
    return jsonify({"url":url_for("view_shared_report", token=token, _external=True), "expires_at":rep.expires_at.strftime("%Y-%m-%d %H:%M")})

@app.route("/r/<token>")
def view_shared_report(token):
    rep=SharedReport.query.filter_by(token=token).first()
    if not rep or rep.expires_at < datetime.datetime.utcnow(): return "Report expired or not found", 404
    return render_template("shared_report.html", report=rep)

@app.route("/api/v1/logs/ingest-async", methods=["POST"])
def api_ingest_async():
    auth=request.headers.get("Authorization","")
    if not auth.startswith("Bearer "): return jsonify({"error":"Missing token"}),401
    user=User.query.filter_by(api_key=auth.split(" ",1)[1]).first()
    if not user: return jsonify({"error":"Invalid API key"}),401
    data=request.get_json(force=True, silent=True) or {}; raw=data.get("logs",""); app_n=data.get("application","api-source")
    job=IngestionJob(user_id=user.id, source="api", filename=app_n, total_bytes=len(raw.encode("utf-8", errors="ignore")), status="queued")
    db.session.add(job); db.session.commit()
    def run_job(app_obj, jid, uid, raw_text, env, appname):
        with app_obj.app_context():
            j=db.session.get(IngestionJob,jid); j.status="running"; j.started_at=datetime.datetime.utcnow(); db.session.commit()
            try:
                u=db.session.get(User,uid); res=analyse_log_text(raw_text,"",env,appname)
                ls=LogSession(user_id=uid, environment=env, filename=appname,total_lines=res["total"], error_count=res["errors"], warn_count=res["warns"], avg_latency=res["latency"], apps_found=",".join(res["apps"]))
                db.session.add(ls); db.session.commit(); threading.Thread(target=persist_raw_upload, args=(uid,ls.id,appname,raw_text), daemon=True).start()
                j.status="success"; j.total_lines=res["total"]; j.finished_at=datetime.datetime.utcnow(); db.session.commit()
            except Exception as e:
                j.status="failed"; j.error=str(e)[:2000]; j.finished_at=datetime.datetime.utcnow(); db.session.commit()
    threading.Thread(target=run_job, args=(app,job.id,user.id,raw,data.get("environment","PROD"),app_n), daemon=True).start()
    return jsonify({"status":"queued","job_id":job.id})

@app.route("/ingestion/jobs")
@login_required
def ingestion_jobs():
    user=get_current_user(); jobs=IngestionJob.query.filter_by(user_id=user.id).order_by(IngestionJob.created_at.desc()).limit(50).all()
    return jsonify([{"id":j.id,"source":j.source,"file":j.filename,"status":j.status,"bytes":j.total_bytes,"lines":j.total_lines,"error":j.error,"created_at":j.created_at.strftime("%Y-%m-%d %H:%M:%S"),"finished_at":j.finished_at.strftime("%Y-%m-%d %H:%M:%S") if j.finished_at else None} for j in jobs])

# ── Profile / API key ─────────────────────────────────────────────────────────
@app.route("/profile/apikey", methods=["POST"])
@login_required
def rotate_api_key():
    user = get_current_user()
    if user is None:
        return jsonify({"error": "Session expired. Please login again."}), 401
    user.api_key = secrets.token_hex(32)
    audit_event(user, "api_key.rotate", "profile", {})
    db.session.commit()
    return jsonify({"api_key": user.api_key, "rotated_at": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")})


@app.route("/saved-searches", methods=["GET", "POST", "DELETE"])
@login_required
def saved_searches():
    user = get_current_user()
    if request.method == "POST":
        data = request.get_json(force=True, silent=True) or {}
        row = SavedSearch(user_id=user.id, title=str(data.get("title") or "Saved search")[:140], query=str(data.get("query") or "")[:500])
        db.session.add(row)
        audit_event(user, "saved_search.create", row.title, {"query": row.query})
        db.session.commit()
        return jsonify({"id": row.id, "status":"created"})
    if request.method == "DELETE":
        row = SavedSearch.query.filter_by(user_id=user.id, id=request.args.get("id")).first()
        if row:
            audit_event(user, "saved_search.delete", row.title)
            db.session.delete(row)
            db.session.commit()
        return jsonify({"status":"deleted"})
    rows = SavedSearch.query.filter_by(user_id=user.id).order_by(SavedSearch.created_at.desc()).all()
    return jsonify([{"id": r.id, "title": r.title, "query": r.query, "at": r.created_at.strftime("%Y-%m-%d %H:%M")} for r in rows])

@app.route("/dashboard-widgets", methods=["GET", "POST", "DELETE"])
@login_required
def dashboard_widgets():
    user = get_current_user()
    if request.method == "POST":
        data = request.get_json(force=True, silent=True) or {}
        row = DashboardWidget(user_id=user.id, title=str(data.get("title") or data.get("type") or "Widget")[:140], widget_type=str(data.get("type") or "Errors")[:80], config_json=json.dumps(data.get("config") or {}))
        db.session.add(row)
        audit_event(user, "dashboard_widget.create", row.title, {"type": row.widget_type})
        db.session.commit()
        return jsonify({"id": row.id, "status":"created"})
    if request.method == "DELETE":
        row = DashboardWidget.query.filter_by(user_id=user.id, id=request.args.get("id")).first()
        if row:
            audit_event(user, "dashboard_widget.delete", row.title)
            db.session.delete(row)
            db.session.commit()
        return jsonify({"status":"deleted"})
    usage = storage_status(user)
    sessions = LogSession.query.filter_by(user_id=user.id).all()
    errors = sum(x.error_count or 0 for x in sessions)
    warns = sum(x.warn_count or 0 for x in sessions)
    rows = DashboardWidget.query.filter_by(user_id=user.id).order_by(DashboardWidget.created_at.asc()).all()
    def value_for(t):
        low = (t or "").lower()
        if "error" in low: return errors
        if "latency" in low: return f"{round(sum(x.avg_latency or 0 for x in sessions)/max(1,len(sessions)))}ms"
        if "trace" in low: return sum(x.total_lines or 0 for x in sessions)
        if "application" in low or "app" in low: return len(set(",".join([x.apps_found or "" for x in sessions]).split(",")) - {""})
        if "checkout" in low: return "auto-detected"
        if "ingestion" in low: return f"{usage['mb']} MB"
        if "health" in low: return max(0, 100 - min(100, errors//10))
        return "ready"
    return jsonify([{"id": r.id, "title": r.title, "type": r.widget_type, "value": value_for(r.widget_type)} for r in rows])

@app.route("/incidents", methods=["GET", "POST"])
@login_required
def incidents():
    user = get_current_user()
    if request.method == "POST":
        data = request.get_json(force=True, silent=True) or {}
        sessions = LogSession.query.filter_by(user_id=user.id).order_by(LogSession.created_at.desc()).limit(5).all()
        severity = min(100, sum(x.error_count or 0 for x in sessions)//5 + sum(x.warn_count or 0 for x in sessions)//25)
        apps = sorted(set(",".join([x.apps_found or "" for x in sessions]).split(",")) - {""})
        row = Incident(user_id=user.id, title=str(data.get("title") or "Production incident")[:220], owner=str(data.get("owner") or "")[:120], status=str(data.get("status") or "Open")[:40], severity=severity, impacted_apis=", ".join(apps[:8]), evidence_json=json.dumps(["Created from current ObserveX dataset", "Use Log Search and Trace Explorer for supporting evidence"]))
        db.session.add(row)
        audit_event(user, "incident.create", row.title, {"severity": severity})
        db.session.commit()
        return jsonify({"id": row.id, "status":"created"})
    rows = Incident.query.filter_by(user_id=user.id).order_by(Incident.updated_at.desc()).all()
    return jsonify([{"id": r.id, "title": r.title, "severity": r.severity, "impacted_apis": r.impacted_apis, "owner": r.owner, "status": r.status, "notes": r.notes, "at": r.created_at.strftime("%Y-%m-%d %H:%M")} for r in rows])

@app.route("/incidents/<int:incident_id>", methods=["POST"])
@login_required
def update_incident(incident_id):
    user = get_current_user()
    row = Incident.query.filter_by(user_id=user.id, id=incident_id).first_or_404()
    data = request.get_json(force=True, silent=True) or {}
    row.status = str(data.get("status") or row.status)[:40]
    row.owner = str(data.get("owner") or row.owner)[:120]
    row.notes = str(data.get("notes") or row.notes)[:4000]
    row.updated_at = datetime.datetime.utcnow()
    audit_event(user, "incident.update", row.title, {"status": row.status})
    db.session.commit()
    return jsonify({"status":"updated"})

@app.route("/log-metrics")
@login_required
def log_metrics():
    user = get_current_user()
    sessions = LogSession.query.filter_by(user_id=user.id).order_by(LogSession.created_at.desc()).limit(50).all()
    total = sum(x.total_lines or 0 for x in sessions)
    errors = sum(x.error_count or 0 for x in sessions)
    warns = sum(x.warn_count or 0 for x in sessions)
    success = max(0, total - errors - warns)
    checkouts = sum(1 for x in sessions if "checkout" in (x.apps_found or "").lower() or "checkout" in (x.filename or "").lower())
    avg_errors = (sum(x.error_count or 0 for x in sessions[1:]) / max(1, len(sessions)-1)) if len(sessions) > 1 else 0
    status = "Spike" if sessions and (sessions[0].error_count or 0) > max(10, avg_errors * 2) else "Normal"
    severity = min(100, errors//10 + warns//30)
    return jsonify({
        "ingested_lines": total, "errors": errors, "warnings": warns, "success": success,
        "checkouts": checkouts, "severity": severity,
        "metrics": [
            {"name":"Error count", "value": errors}, {"name":"Warning count", "value": warns},
            {"name":"Success/Info signals", "value": success}, {"name":"Sessions analysed", "value": len(sessions)}
        ],
        "anomaly": {"status": status, "reason": "Latest upload has elevated errors versus previous baseline." if status == "Spike" else "No unusual spike detected yet. Baseline improves with more uploads."}
    })

@app.route("/marketplace")
@login_required
def marketplace():
    return jsonify([
        {"name":"MuleSoft", "icon":"🧩", "status":"available", "description":"Parse Mule runtime logs, processors, event IDs and flows."},
        {"name":"AWS CloudWatch", "icon":"☁️", "status":"available", "description":"Ingest application and Lambda logs via connector configuration."},
        {"name":"Amazon S3", "icon":"🪣", "status":"available", "description":"Schedule bucket/prefix pulls for large log files."},
        {"name":"Slack", "icon":"💬", "status":"available", "description":"Send incident and alert notifications to channels."},
        {"name":"Microsoft Teams", "icon":"👥", "status":"available", "description":"Notify support and SRE teams from alert escalations."},
        {"name":"Jira", "icon":"🎫", "status":"planned", "description":"Create and sync incident tickets."},
        {"name":"GitHub", "icon":"🐙", "status":"planned", "description":"Correlate incidents with deployments and commits."},
        {"name":"Webhook", "icon":"🔗", "status":"available", "description":"Generic outbound integration for any workflow."}
    ])

@app.route("/billing/usage")
@login_required
def billing_usage():
    user = get_current_user()
    ws = ensure_default_workspace(user)
    limits = get_plan_limits(ws.plan if ws else "starter")
    usage = storage_status(user)
    members = WorkspaceMember.query.filter_by(workspace_id=ws.id).count() if ws else 1
    alerts = AlertRule.query.filter_by(user_id=user.id).count()
    return jsonify({
        "plan": ws.plan if ws else "starter", "storage_mb": usage["mb"],
        "ingestion_gb_month": round(usage["bytes"] / 1024 / 1024 / 1024, 3),
        "users": members, "retention_days": limits["retention_days"], "alerts": alerts,
        "limits": limits
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
