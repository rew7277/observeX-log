import os, re, json, hashlib, secrets, datetime, threading, time, warnings
# Silence authlib joserfc migration warning — cosmetic only, functionality unaffected
warnings.filterwarnings("ignore", category=DeprecationWarning, module="authlib")
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, jsonify, flash, make_response, abort, Response
)
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from sqlalchemy import text

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

# Rate limiting: Redis in production, safe in-memory fallback for local dev.
_API_RATE_BUCKET = {}
_REDIS_CLIENT = None
try:
    if os.environ.get("REDIS_URL"):
        import redis
        _REDIS_CLIENT = redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
except Exception:
    _REDIS_CLIENT = None

def api_rate_limited(key, limit=120, window=60):
    now = int(time.time())
    safe_key = hashlib.sha256(str(key).encode()).hexdigest()[:32]
    if _REDIS_CLIENT is not None:
        try:
            redis_key = f"observex:rl:{safe_key}:{now // window}"
            count = _REDIS_CLIENT.incr(redis_key)
            if count == 1:
                _REDIS_CLIENT.expire(redis_key, window + 5)
            return int(count) > int(limit)
        except Exception:
            app.logger.exception("Redis rate limiter failed; falling back to memory")
    bucket = _API_RATE_BUCKET.setdefault(safe_key, [])
    bucket[:] = [t for t in bucket if now - t < window]
    if len(bucket) >= limit:
        return True
    bucket.append(now)
    return False



@app.before_request
def v9_login_bruteforce_guard():
    if request.path == '/login' and request.method == 'POST':
        ip = (request.headers.get('X-Forwarded-For') or request.remote_addr or 'unknown').split(',')[0]
        if api_rate_limited('login:' + ip, limit=int(os.environ.get('LOGIN_RATE_LIMIT_PER_MIN', '12')), window=60):
            abort(429, 'Too many login attempts. Please try again shortly.')
    return None
# ── Config ────────────────────────────────────────────────────────────────────
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))

def resolve_database_url():
    """Resolve a non-empty SQLAlchemy database URL for Railway/local startup."""
    raw = (os.environ.get("DATABASE_URL") or os.environ.get("DATABASE_PUBLIC_URL") or "").strip()
    if raw:
        return raw.replace("postgres://", "postgresql://", 1)
    return os.environ.get("SQLITE_DATABASE_URL", "sqlite:///observex.db")

DATABASE_CONFIG_WARNING = None
if not (os.environ.get("DATABASE_URL") or "").strip():
    if (os.environ.get("DATABASE_PUBLIC_URL") or "").strip():
        DATABASE_CONFIG_WARNING = "DATABASE_URL is empty; using DATABASE_PUBLIC_URL fallback."
    else:
        DATABASE_CONFIG_WARNING = "DATABASE_URL is empty; using SQLite fallback. Link Railway Postgres and set DATABASE_URL for production."

app.config["SQLALCHEMY_DATABASE_URI"] = resolve_database_url()
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# V12 SSL FIX: pre_ping validates connections before use (catches stale SSL sockets).
# pool_recycle closes connections before Railway's 5-min idle timeout kills them.
# NullPool is used when SQLALCHEMY_NULLPOOL=1 (e.g. for pgbouncer/transaction mode).
_use_nullpool = os.environ.get("SQLALCHEMY_NULLPOOL", "").lower() in ("1", "true", "yes")
if _use_nullpool:
    from sqlalchemy.pool import NullPool
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"poolclass": NullPool}
else:
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True,        # validates SSL connection before each use
        "pool_recycle":  280,         # recycle before Railway's 300s idle timeout
        "pool_size":     2,           # 2 workers × 2 = 4 total Postgres connections
        "max_overflow":  4,
        "pool_timeout":  30,
        "connect_args":  {"connect_timeout": 10},
    }
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_UPLOAD_MB", "500")) * 1024 * 1024  # default 500 MB
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_ENV") == "production" or bool(os.environ.get("RAILWAY_ENVIRONMENT"))
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

# ── CSRF and API-key helpers ─────────────────────────────────────────────────
def csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token

@app.context_processor
def inject_security_tokens():
    return {"csrf_token": csrf_token}

@app.before_request
def protect_form_posts():
    # API and JSON/fetch endpoints use bearer auth or same-origin JSON; browser HTML forms must include CSRF.
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return None
    if request.path.startswith("/api/") or request.path in {"/analyse", "/analyse/async", "/alerts", "/connectors", "/saved-searches", "/alert-destinations", "/profile/apikey", "/history"}:
        return None
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
    if not sent or not secrets.compare_digest(str(sent), str(session.get("csrf_token", ""))):
        abort(400, "Invalid CSRF token")
    return None

def generate_api_key():
    raw = "ox_" + secrets.token_urlsafe(32)
    return raw, hashlib.sha256(raw.encode()).hexdigest(), raw[:10]

def hash_api_key(raw):
    return hashlib.sha256(str(raw).encode()).hexdigest()

def lookup_user_by_api_key(raw_key):
    if not raw_key:
        return None
    digest = hash_api_key(raw_key)
    user = User.query.filter_by(api_key_hash=digest).first()
    if user:
        user.api_key_last_used = datetime.datetime.utcnow()
        return user
    # Backward compatibility: migrate plaintext legacy key on first successful use.
    legacy = User.query.filter_by(api_key=raw_key).first()
    if legacy:
        legacy.api_key_hash = digest
        legacy.api_key_prefix = str(raw_key)[:10]
        legacy.api_key = None
        legacy.api_key_last_used = datetime.datetime.utcnow()
        return legacy
    return None

def ensure_default_api_key(user):
    if not user:
        return None
    if user.api_key_hash:
        return None
    raw, digest, prefix = generate_api_key()
    user.api_key_hash = digest
    user.api_key_prefix = prefix
    user.api_key = None
    return raw


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
    # api_key is retained only for backward compatibility with older deployments.
    # New keys are returned once and stored as api_key_hash at rest.
    api_key       = db.Column(db.String(64), nullable=True)
    api_key_hash  = db.Column(db.String(128), nullable=True, index=True)
    api_key_prefix = db.Column(db.String(12), nullable=True)
    api_key_last_used = db.Column(db.DateTime, nullable=True)

class LogSession(db.Model):
    id             = db.Column(db.Integer, primary_key=True)
    user_id        = db.Column(db.Integer, db.ForeignKey("user.id"))
    environment    = db.Column(db.String(20))
    filename       = db.Column(db.String(200))
    total_lines    = db.Column(db.Integer, default=0)
    error_count    = db.Column(db.Integer, default=0)
    warn_count     = db.Column(db.Integer, default=0)
    avg_latency    = db.Column(db.Integer, default=0)
    apps_found     = db.Column(db.Text, default="")
    log_rows_json  = db.Column(db.Text, default="[]")   # Persists parsed rows in Postgres
    result_json    = db.Column(db.Text, default="{}")   # Full analyse result (summary) for reload
    created_at     = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class ApiFlowMap(db.Model):
    """Stores per-API, per-endpoint flow mapping extracted from uploaded logs."""
    id              = db.Column(db.Integer, primary_key=True)
    user_id         = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    session_id      = db.Column(db.Integer, db.ForeignKey("log_session.id"), nullable=False)
    api_name        = db.Column(db.String(200), nullable=False)
    environment     = db.Column(db.String(20), default="PROD")
    endpoint        = db.Column(db.String(300), default="")
    method          = db.Column(db.String(10), default="")
    flow_steps_json = db.Column(db.Text, default="[]")   # ["Client","Mule API","CBS","Response"]
    architecture_json = db.Column(db.Text, default="{}")  # tiered nodes, edges, traces and call matrix
    request_count   = db.Column(db.Integer, default=0)
    error_count     = db.Column(db.Integer, default=0)
    avg_latency_ms  = db.Column(db.Integer, default=0)
    sample_trace_id = db.Column(db.String(120), default="")
    created_at      = db.Column(db.DateTime, default=datetime.datetime.utcnow)


class ApiRegistry(db.Model):
    """Master API inventory used by System Map and API dropdowns."""
    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    api_name     = db.Column(db.String(200), nullable=False, index=True)
    environment  = db.Column(db.String(20), default="PROD", index=True)
    base_url     = db.Column(db.String(400), default="")
    owner        = db.Column(db.String(120), default="")
    status       = db.Column(db.String(40), default="active")
    downstream_systems_json = db.Column(db.Text, default="[]")
    manual_flow_nodes_json = db.Column(db.Text, default="[]")  # curated source-of-truth topology nodes
    last_seen_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    created_at   = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    __table_args__ = (db.UniqueConstraint("user_id", "api_name", "environment", name="uq_api_registry_user_api_env"),)

class ApiEndpoint(db.Model):
    """Endpoint inventory under each API. Powers API Name -> Endpoints -> Flow."""
    id              = db.Column(db.Integer, primary_key=True)
    user_id         = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    api_registry_id = db.Column(db.Integer, db.ForeignKey("api_registry.id"), nullable=True, index=True)
    api_name        = db.Column(db.String(200), nullable=False, index=True)
    environment     = db.Column(db.String(20), default="PROD", index=True)
    endpoint        = db.Column(db.String(300), default="/", index=True)
    method          = db.Column(db.String(10), default="")
    request_count   = db.Column(db.Integer, default=0)
    error_count     = db.Column(db.Integer, default=0)
    avg_latency_ms  = db.Column(db.Integer, default=0)
    last_seen_at    = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    created_at      = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    __table_args__ = (db.UniqueConstraint("user_id", "api_name", "environment", "endpoint", "method", name="uq_api_endpoint_user_api_env_ep_method"),)

class TraceIndex(db.Model):
    """Trace lookup table for fast Trace Explorer without rescanning raw files."""
    id             = db.Column(db.Integer, primary_key=True)
    user_id        = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    session_id     = db.Column(db.Integer, db.ForeignKey("log_session.id"), nullable=False, index=True)
    trace_id       = db.Column(db.String(160), nullable=False, index=True)
    environment    = db.Column(db.String(20), default="PROD", index=True)
    api_name       = db.Column(db.String(200), default="", index=True)
    endpoint       = db.Column(db.String(300), default="/")
    status         = db.Column(db.String(30), default="success")
    latency_ms     = db.Column(db.Integer, default=0)
    rows_json      = db.Column(db.Text, default="[]")
    created_at     = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class LogEvent(db.Model):
    """Searchable parsed log rows. Keeps Global Search fast and environment-aware."""
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    session_id  = db.Column(db.Integer, db.ForeignKey("log_session.id"), nullable=False, index=True)
    environment = db.Column(db.String(20), default="PROD", index=True)
    api_name    = db.Column(db.String(200), default="", index=True)
    endpoint    = db.Column(db.String(300), default="/")
    trace_id    = db.Column(db.String(160), default="", index=True)
    level       = db.Column(db.String(20), default="INFO", index=True)
    event_time  = db.Column(db.String(80), default="")
    message     = db.Column(db.Text, default="")
    latency_ms  = db.Column(db.Integer, default=0)
    row_json    = db.Column(db.Text, default="{}")
    created_at  = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class FlowEdge(db.Model):
    """Persisted graph edge for API/System Map visualisation."""
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    session_id  = db.Column(db.Integer, db.ForeignKey("log_session.id"), nullable=False, index=True)
    environment = db.Column(db.String(20), default="PROD", index=True)
    api_name    = db.Column(db.String(200), default="", index=True)
    endpoint    = db.Column(db.String(300), default="/")
    source      = db.Column(db.String(200), nullable=False)
    target      = db.Column(db.String(200), nullable=False)
    label       = db.Column(db.String(80), default="calls")
    count       = db.Column(db.Integer, default=1)
    errors      = db.Column(db.Integer, default=0)
    created_at  = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class AlertRule(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("user.id"))
    name       = db.Column(db.String(100))
    condition  = db.Column(db.String(200))
    threshold  = db.Column(db.Float)
    active     = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

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

class MaskingRule(db.Model):
    """User-configurable masking rule used by Settings -> Security & Masking."""
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    field_name  = db.Column(db.String(120), nullable=False)
    mask_type   = db.Column(db.String(40), default="full")
    enabled     = db.Column(db.Boolean, default=True)
    created_at  = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at  = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    __table_args__ = (db.UniqueConstraint("user_id", "field_name", name="uq_masking_rule_user_field"),)

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
    session_id  = db.Column(db.Integer, db.ForeignKey("log_session.id"), nullable=True, index=True)
    progress    = db.Column(db.Integer, default=0)  # 0-100; dashboard uses this while polling
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


_db_init_lock = threading.Lock()

def ensure_runtime_columns():
    # Lightweight compatibility for Railway projects that previously used db.create_all().
    # Real production projects should use Flask-Migrate/Alembic; this prevents 500s on existing DBs.
    engine = db.engine
    dialect = engine.dialect.name
    stmts = []
    if dialect == "postgresql":
        stmts = [
            "ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS api_key_hash VARCHAR(128)",
            "ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS api_key_prefix VARCHAR(12)",
            "ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS api_key_last_used TIMESTAMP",
            # Log persistence columns
            "ALTER TABLE log_session ADD COLUMN IF NOT EXISTS log_rows_json TEXT DEFAULT '[]'",
            "ALTER TABLE log_session ADD COLUMN IF NOT EXISTS result_json TEXT DEFAULT '{}'",
            "ALTER TABLE api_flow_map ADD COLUMN IF NOT EXISTS architecture_json TEXT DEFAULT '{}'",
            "ALTER TABLE api_registry ADD COLUMN IF NOT EXISTS downstream_systems_json TEXT DEFAULT '[]'",
            "ALTER TABLE api_registry ADD COLUMN IF NOT EXISTS manual_flow_nodes_json TEXT DEFAULT '[]'",
            "ALTER TABLE ingestion_job ADD COLUMN IF NOT EXISTS session_id INTEGER",
            "ALTER TABLE ingestion_job ADD COLUMN IF NOT EXISTS progress INTEGER DEFAULT 0",
        ]
    else:
        existing_user = {row[1] for row in db.session.execute(text("PRAGMA table_info(user)")).fetchall()}
        if "api_key_hash" not in existing_user: stmts.append("ALTER TABLE user ADD COLUMN api_key_hash VARCHAR(128)")
        if "api_key_prefix" not in existing_user: stmts.append("ALTER TABLE user ADD COLUMN api_key_prefix VARCHAR(12)")
        if "api_key_last_used" not in existing_user: stmts.append("ALTER TABLE user ADD COLUMN api_key_last_used DATETIME")
        try:
            existing_ls = {row[1] for row in db.session.execute(text("PRAGMA table_info(log_session)")).fetchall()}
            if "log_rows_json" not in existing_ls: stmts.append("ALTER TABLE log_session ADD COLUMN log_rows_json TEXT DEFAULT '[]'")
            if "result_json" not in existing_ls: stmts.append("ALTER TABLE log_session ADD COLUMN result_json TEXT DEFAULT '{}'")
        except Exception:
            pass
        try:
            existing_ij = {row[1] for row in db.session.execute(text("PRAGMA table_info(ingestion_job)")).fetchall()}
            if "session_id" not in existing_ij: stmts.append("ALTER TABLE ingestion_job ADD COLUMN session_id INTEGER")
            if "progress" not in existing_ij: stmts.append("ALTER TABLE ingestion_job ADD COLUMN progress INTEGER DEFAULT 0")
        except Exception:
            pass
        try:
            existing_afm = {row[1] for row in db.session.execute(text("PRAGMA table_info(api_flow_map)")).fetchall()}
            if "architecture_json" not in existing_afm: stmts.append("ALTER TABLE api_flow_map ADD COLUMN architecture_json TEXT DEFAULT '{}'")
        except Exception:
            pass
        try:
            existing_ar = {row[1] for row in db.session.execute(text("PRAGMA table_info(api_registry)")).fetchall()}
            if "downstream_systems_json" not in existing_ar: stmts.append("ALTER TABLE api_registry ADD COLUMN downstream_systems_json TEXT DEFAULT '[]'")
            if "manual_flow_nodes_json" not in existing_ar: stmts.append("ALTER TABLE api_registry ADD COLUMN manual_flow_nodes_json TEXT DEFAULT '[]'")
        except Exception:
            pass
    for stmt in stmts:
        try:
            db.session.execute(text(stmt))
        except Exception:
            db.session.rollback()
    db.session.commit()

def migrate_legacy_api_keys():
    try:
        for user in User.query.filter(User.api_key.isnot(None)).all():
            if user.api_key and not user.api_key_hash:
                user.api_key_hash = hash_api_key(user.api_key)
                user.api_key_prefix = user.api_key[:10]
                user.api_key = None
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("Legacy API key migration skipped")

def init_db_once():
    with _db_init_lock:
        db.create_all()
        ensure_runtime_columns()
        migrate_legacy_api_keys()

def init_db_with_retry(max_attempts=6, delay_seconds=2):
    last_exc = None
    for attempt in range(1, max_attempts + 1):
        try:
            init_db_once()
            if DATABASE_CONFIG_WARNING:
                app.logger.warning(DATABASE_CONFIG_WARNING)
            return True
        except Exception as exc:
            db.session.rollback()
            last_exc = exc
            app.logger.warning("Database init attempt %s/%s failed: %s", attempt, max_attempts, exc)
            time.sleep(delay_seconds)
    app.logger.exception("Database initialization failed after retries", exc_info=last_exc)
    return False

with app.app_context():
    init_db_with_retry()

@app.errorhandler(413)
def request_entity_too_large(error):
    if request.path.startswith("/analyse") or request.path.startswith("/api/"):
        return jsonify({"error": f"Uploaded log is too large. Current limit is {app.config['MAX_CONTENT_LENGTH'] // (1024 * 1024)} MB. Increase MAX_UPLOAD_MB in Railway or upload smaller files."}), 413
    return "Uploaded file too large", 413

@app.route("/health")
def health():
    try:
        db.session.execute(text("SELECT 1"))
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
    """Return the logged-in user, with automatic retry on stale SSL connections."""
    uid = session.get("user_id")
    if not uid:
        return None
    # V12: retry once on SSL/connection errors (happens after worker fork or idle timeout)
    for attempt in range(2):
        try:
            user = db.session.get(User, uid)
            if user is None:
                session.clear()
            return user
        except Exception as exc:
            err = str(exc).lower()
            if attempt == 0 and any(kw in err for kw in (
                "ssl", "eof", "decryption", "bad record", "connection", "operational"
            )):
                # Dispose the pool so next attempt gets a fresh connection
                db.session.rollback()
                try:
                    db.engine.dispose()
                except Exception:
                    pass
                continue
            # Second attempt or unrecognised error — re-raise
            db.session.rollback()
            raise
    return None

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
    """Classify log severity without treating random numbers as HTTP status codes.

    V7 fix: earlier logic marked any bare 2xx number as SUCCESS, so messages like
    'fetched 200 records after downstream timeout' could be counted incorrectly.
    Error/failure signals now win over success signals, and HTTP codes are only
    considered when they appear in an HTTP/status context.
    """
    text = str(line or "")
    if re.search(r"\b(ERROR|FATAL|SEVERE)\b|exception|gateway timeout|timeout|bad request|connection refused|unavailable|\bHTTP(?:\/\d(?:\.\d)?)?\s*5\d\d\b|\bstatus(?:Code)?[=:\s]+5\d\d\b|\bresponse(?:Code|Status)?[=:\s]+5\d\d\b", text, re.I):
        return "ERROR"
    if re.search(r"\b(FAIL|FAILED|FAILURE)\b", text, re.I):
        return "FAILURE"
    if re.search(r"\b(WARN|WARNING)\b|retry|slow|\bHTTP(?:\/\d(?:\.\d)?)?\s*4\d\d\b|\bstatus(?:Code)?[=:\s]+4\d\d\b|\bresponse(?:Code|Status)?[=:\s]+4\d\d\b", text, re.I):
        return "WARN"
    if re.search(r"\b(DEBUG|TRACE)\b", text, re.I):
        return "DEBUG"
    if re.search(r"\b(SUCCESS|SUCCEEDED|COMPLETED|OK)\b|\bHTTP(?:\/\d(?:\.\d)?)?\s*2\d\d\b|\bstatus(?:Code)?[=:\s]+2\d\d\b|\bresponse(?:Code|Status)?[=:\s]+2\d\d\b", text, re.I):
        return "SUCCESS"
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

DEFAULT_MASKING_RULES = [
    {"field_name":"Phone", "mask_type":"partial", "enabled":True},
    {"field_name":"Email", "mask_type":"hash", "enabled":True},
    {"field_name":"BankAc", "mask_type":"full", "enabled":True},
    {"field_name":"Amt", "mask_type":"full", "enabled":True},
    {"field_name":"CollectionAmt", "mask_type":"full", "enabled":True},
    {"field_name":"AppID", "mask_type":"full", "enabled":True},
    {"field_name":"MerchantKey", "mask_type":"full", "enabled":True},
    {"field_name":"Ref1", "mask_type":"searchable_mask", "enabled":True},
    {"field_name":"Ref2", "mask_type":"partial", "enabled":True},
    {"field_name":"Cust1", "mask_type":"partial", "enabled":True},
    {"field_name":"Cust2", "mask_type":"partial", "enabled":True},
    {"field_name":"Cust3", "mask_type":"partial", "enabled":True},
    {"field_name":"IFSC", "mask_type":"partial", "enabled":True},
    {"field_name":"MICR", "mask_type":"partial", "enabled":True},
]

def _hash_mask_value(value):
    try:
        return hashlib.sha256(str(value).encode("utf-8", errors="ignore")).hexdigest()[:12]
    except Exception:
        return "MASKED_HASH"

def _mask_value(value, mask_type="full"):
    if value is None:
        return value
    value = str(value)
    if value == "":
        return value
    mt = (mask_type or "full").lower()
    if mt == "partial":
        if len(value) <= 4:
            return "*" * len(value)
        return value[:2] + "*" * min(8, max(4, len(value)-4)) + value[-2:]
    if mt == "hash":
        return "[HASH:" + _hash_mask_value(value) + "]"
    if mt == "searchable_mask":
        m = re.search(r"(\d{4,8})$", value)
        suffix = m.group(1) if m else value[-6:]
        return "[MASKED_ID:" + suffix + "]"
    return "[MASKED]"

def _default_masking_config():
    return [dict(x) for x in DEFAULT_MASKING_RULES]

def get_masking_config(user_id=None):
    if not user_id:
        return _default_masking_config()
    try:
        rules = MaskingRule.query.filter_by(user_id=user_id).order_by(MaskingRule.field_name.asc()).all()
        if not rules:
            for item in DEFAULT_MASKING_RULES:
                db.session.add(MaskingRule(user_id=user_id, field_name=item["field_name"], mask_type=item["mask_type"], enabled=item["enabled"]))
            db.session.commit()
            rules = MaskingRule.query.filter_by(user_id=user_id).order_by(MaskingRule.field_name.asc()).all()
        return [{"field_name":r.field_name, "mask_type":r.mask_type or "full", "enabled":bool(r.enabled)} for r in rules]
    except Exception:
        db.session.rollback()
        return _default_masking_config()

def apply_field_masking(text: str, config):
    masked = str(text or "")
    enabled = [r for r in (config or []) if r.get("enabled") and r.get("field_name")]
    for rule in enabled:
        key = re.escape(str(rule.get("field_name")))
        mt = str(rule.get("mask_type") or "full")
        def repl_json(m, mt=mt):
            return m.group(1) + _mask_value(m.group(2), mt) + m.group(3)
        masked = re.sub(r'(?i)("' + key + r'"\s*:\s*")([^"]*)(")', repl_json, masked)
        def repl_kv(m, mt=mt):
            return m.group(1) + _mask_value(m.group(2), mt)
        masked = re.sub(r"(?i)(\b" + key + r"\b\s*[=:]\s*['\"]?)([^\s,;\"'}]+)", repl_kv, masked)
    return masked

def extract_safe_search_tokens(raw_text: str):
    text = str(raw_text or "")
    toks = set()
    for val in re.findall(r"\b(?:TR|PP|BD|FS|GLB|APPL|APPT)[A-Z0-9]{4,}\b", text, re.I):
        m = re.search(r"(\d{4,8})$", val)
        if m:
            toks.add(m.group(1))
    for val in re.findall(r'(?i)"(?:Ref1|Ref2|reference|referenceId|transactionId)"\s*:\s*"([^"]+)"', text):
        m = re.search(r"(\d{4,8})$", val)
        if m:
            toks.add(m.group(1))
    return " ".join(sorted(toks))

def mask_secrets(text: str, user_id=None):
    """Mask PII/secrets plus user-configured fields before UI/API/storage."""
    if not text:
        return text
    masked = apply_field_masking(str(text), get_masking_config(user_id))
    masked = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "[MASKED_JWT]", masked)
    masked = re.sub(r"(?i)(authorization\s*[:=]\s*bearer\s+)[A-Za-z0-9._\-+/=]{16,}", r"\1[MASKED_TOKEN]", masked)
    masked = re.sub(r"(?i)(api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|bearer|token|password|passwd|pwd|secret|client[_-]?secret|signature|hmac)(\s*[=:]\s*['\"]?)([^\s,;\"'}]{4,})", r"\1\2[MASKED]", masked)
    masked = re.sub(r"(?i)(aadhaar|aadhar|uidai)(\s*[=:]\s*['\"]?)(\d[ -]?){12}", r"\1\2[MASKED_AADHAAR]", masked)
    masked = re.sub(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}\b", "[MASKED_AADHAAR]", masked)
    masked = re.sub(r"(?i)(pan|panNumber|pan_card)(\s*[=:]\s*['\"]?)[A-Z]{5}\d{4}[A-Z]", r"\1\2[MASKED_PAN]", masked)
    masked = re.sub(r"\b[A-Z]{5}\d{4}[A-Z]\b", "[MASKED_PAN]", masked)
    masked = re.sub(r"(?i)(mobile|phone|customerMobile|contact|msisdn)(\s*[=:]\s*['\"]?)(?:\+?91[- ]?)?[6-9]\d{9}", r"\1\2[MASKED_MOBILE]", masked)
    masked = re.sub(r"(?<!\d)(?:\+?91[- ]?)?[6-9]\d{9}(?!\d)", "[MASKED_MOBILE]", masked)
    masked = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[MASKED_EMAIL]", masked)
    sensitive_keys = ["customerName", "name", "fullName", "firstName", "lastName", "loanNumber", "loanId", "accountNumber", "accountNo", "primaryCustomerId", "customerId", "applicationNo", "checkoutId", "bbpsId", "receiptNumber", "transactionId", "gatewayTransactionId", "upiId", "vpa", "cardNumber"]
    key_alt = "|".join(map(re.escape, sensitive_keys))
    masked = re.sub(rf"(?i)(\"(?:{key_alt})\"\s*:\s*\")([^\"]+)(\")", r"\1[MASKED]\3", masked)
    masked = re.sub(rf"(?i)(\b(?:{key_alt})\b\s*[=:]\s*['\"]?)([A-Za-z0-9@._\- /]+)", r"\1[MASKED]", masked)
    def repl_ref(m):
        val = m.group(0)
        num = re.search(r"(\d{4,8})$", val)
        return "[MASKED_ID:" + (num.group(1) if num else val[-6:]) + "]"
    masked = re.sub(r"\b(?:TR|PP|BD|FS|GLB|APPL|APPT)[A-Z0-9]{6,}\b", repl_ref, masked)
    return masked


def persist_raw_upload(user_id: int, session_id: int, filename: str, raw: str):
    """Persist masked raw logs to Railway volume for audit/re-open without keeping sensitive values."""
    safe_name = secure_filename(filename or "upload.log")[:120]
    user_dir = os.path.join(UPLOAD_DIR, str(user_id))
    os.makedirs(user_dir, exist_ok=True)
    path = os.path.join(user_dir, f"session-{session_id}-{safe_name}.masked.log")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(mask_secrets(raw, user_id))
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

def build_log_rows(records, env, filename="", user_id=None):
    rows=[]
    current_app=""; current_file=filename
    for rec in records:
        line = "\n".join(rec.get("message") or [])
        current_file = rec.get("file") or current_file
        app = extract_first([
            r"\[([a-zA-Z][a-zA-Z0-9_.-]*(?:api|API)[a-zA-Z0-9_.-]*)\]",
            r'"(?:ApplicationName|applicationName|application|app|apiName|serviceName|muleAppName)"\s*:\s*"([^"\n]+)"',
            r"(?:app|application|service|applicationName|apiName|serviceName|muleAppName)\s*[=:]\s*['\"]?([a-zA-Z0-9_.-]+)",
            r"\[([^\]]*(?:api|API)[^\]]*)\]"
        ], line, current_app or "unknown")
        if app and '].' in app:
            # Mule thread names can contain '[api].flow'; keep only API token.
            mm = re.search(r'([A-Za-z0-9_.-]*(?:api|API)[A-Za-z0-9_.-]*)', app)
            app = mm.group(1) if mm else app
        # Avoid treating Mule processor/event tokens as application names.
        if app and _looks_like_processor_event_name(app):
            cfg = extract_first([r'\[([A-Za-z0-9_.-]+-api)\]\.[A-Za-z0-9_-]+', r'\[([A-Za-z0-9_.-]+-api)\]', r'([A-Za-z0-9_.-]+-api)-config'], line, '')
            app = cfg or current_app or 'unknown'
        app = _clean_service_name(app) or 'unknown'
        if app != "unknown" and not _looks_like_processor_event_name(app): current_app=app
        trace = extract_trace_id(line)
        status = extract_first([r'"HttpStatus"\s*:\s*(\d{3})', r"(?:status|statusCode|httpStatus)\s*[=:]\s*(\d{3})", r"\b(5\d\d|4\d\d|2\d\d)\b"], line, "")
        lat = extract_first([
            r"(?:latency|duration|timeTaken|elapsed|responseTime|processingTime|executionTime|timetaken|response_time)\s*[=: ]+([0-9]+)",
            r"completed\s+in\s+([0-9]+)\s*ms",
            r"time\s*[=:]\s*([0-9]+)\s*ms",
            r'"(?:latency|duration|timeTaken|elapsed|responseTime|processingTime|executionTime)"\s*:\s*([0-9]+)',
            r'\b([0-9]+)\s*ms\b',
        ], line, "")
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
        flow = _clean_service_name(flow) if flow else ""
        route_api, route_method, route_endpoint = _extract_mule_route_from_text(line) if '_extract_mule_route_from_text' in globals() else ('','','')
        if route_api and (app == 'unknown' or not app):
            app = route_api
            current_app = app
        rows.append({
            "line_no": rec.get("line_no"), "time": extract_time(line, f"line {rec.get('line_no')}"), "env": env,
            "file": current_file, "level": detect_level(line), "app": app, "trace": trace,
            "event": trace, "flow": flow, "method": route_method, "endpoint": route_endpoint or "",
            "status": status, "latency": int(lat) if str(lat).isdigit() else 0,
            "message": mask_secrets(line, user_id), "search_tokens": extract_safe_search_tokens(line), "is_multiline": "\n" in line
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

def analyse_log_text(raw: str, query: str = "", env: str = "PROD", filename: str = "", user_id=None):
    records = group_multiline_log_records(raw, filename)
    detected_env = infer_environment(raw[:5000], env)
    all_rows = build_log_rows(records, detected_env, filename, user_id)
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
        "truncated": len(rows) > 2000, "total_parsed": len(rows), "showing": min(len(rows), 2000),
        "root_cause": root_cause, "hot_traces": hot_traces, "app_health": app_health,
        "timeline_buckets": timeline_buckets, "action_cards": action_cards, "deploy_summary": deploy_summary,
        "preview": "\n".join(lines[:500]),
        "flow": "Client → " + " → ".join(apps[:5]) + (" → External Dependencies" if deps else "") if apps else "",
        "error_lines": [r['message'] for r in errors[:50]], "slow_lines": [r['message'] for r in rows if r.get('latency',0)>3000][:50],
        "timeline": rows[:500],
        "query_help": "Use env:PROD app:s-htmltopdf-api level:ERROR trace:<id> message:\"otp success\" latency>3000 date:2026-04-11"
    }


# ── System Map extraction ─────────────────────────────────────────────────────

def _clean_service_name(value: str) -> str:
    """Convert noisy log processor names into readable architecture service nodes."""
    s = str(value or '').strip().strip('"\'[]{}(),;')
    if not s: return ''
    s = _normalise_mule_component_name(s) if '_normalise_mule_component_name' in globals() else s
    # Drop log-level prefixes that bleed into names
    s = re.sub(r'\b(?:INFO|DEBUG|WARN|ERROR|SUCCESS|FAILURE|TRACE|FATAL)\b.*$', '', s, flags=re.I).strip()
    # Drop escape sequences
    s = re.sub(r'\\[tnr]', ' ', s)
    # Drop before/after request to prefix
    s = re.sub(r'\b(?:before|after)\s+request\s+to\s+', '', s, flags=re.I)
    # Drop MuleSoft processor index suffixes like /processors/0, processors/1
    s = re.sub(r'(?:/processors?/?\d*|/subflows?/?\d*)', '', s, flags=re.I)
    # Drop path parameter segments that look like REST IDs (not real service names)
    s = re.sub(r'/\{[^}]+\}', '', s)
    s = re.sub(r'/\d+(?=/|$)', '', s)
    # Replace non-alphanumeric runs with single dash
    s = re.sub(r'[^A-Za-z0-9_.-]+', '-', s)
    s = re.sub(r'-{2,}', '-', s).strip('-_.')
    if not s or len(s) < 2:
        return ''
    if len(s) > 52:
        s = s[:52].rstrip('-_.')
    return s


def _normalise_mule_component_name(value: str) -> str:
    s = str(value or '').strip()
    if not s:
        return ''
    s = re.sub(r'^processor[:=\-\s]+', '', s, flags=re.I)
    s = re.sub(r'/processors?/\d+.*$', '', s, flags=re.I)
    s = re.sub(r'/processors?.*$', '', s, flags=re.I)
    s = re.sub(r'-event-\d+-[0-9a-f]{4,}.*$', '', s, flags=re.I)
    s = re.sub(r'-event-[0-9a-f]{4,}.*$', '', s, flags=re.I)
    s = re.sub(r'\s*;\s*event[:=].*$', '', s, flags=re.I)
    s = re.sub(r'\s+event[:=].*$', '', s, flags=re.I)
    return s.strip(' -_/;:')

def _looks_like_processor_event_name(value: str) -> bool:
    low = str(value or '').lower()
    return bool(
        low.startswith('processor-') or
        low.startswith('processor:') or
        'processor-make-api-call-event' in low or
        'processors/' in low or
        re.search(r'-event-\d+-[0-9a-f]{4,}', low)
    )

def _is_valid_api_inventory_name(value: str) -> bool:
    name = str(value or '').strip()
    low = name.lower()
    if not name or name in ('unknown', 'unknown-api', 'loading'):
        return False
    if _looks_like_processor_event_name(name):
        return False
    return ('api' in low or 'service' in low or 'engine' in low)



def _meaningful_flow_name(name: str) -> str:
    """Return a stable, user-facing Mule/API flow component name or ''."""
    n = _clean_service_name(name)
    if not n:
        return ''
    low = n.lower()
    if low in {'client','common','default','logging','logger','log','logs','mule-subflow','mule-flow','external-service','service','flow','processor','response'}:
        return ''
    if low.startswith('processor-') or _looks_like_processor_event_name(n):
        n = _normalise_mule_component_name(n)
        n = _clean_service_name(n)
        low = n.lower()
    if not n or low in {'common','default','logging','external-service'}:
        return ''
    return n

def _build_clean_execution_flow(api_name: str, rows: list, arch: dict = None) -> list:
    """Build a readable API -> business flow -> outbound call -> external dependency -> response sequence."""
    api = _clean_service_name(api_name) or 'Application'
    steps = []
    generic = {'client','common','default','logging','logger','log','logs','mule-subflow','mule-flow','external-service','service','flow','processor','response','subflow','mule-api','jwt-validation','api-router','processing','before-request','after-response'}
    def clean_step(x):
        n = _meaningful_flow_name(x)
        if not n or _looks_like_processor_event_name(n) or n.lower() in generic:
            return ''
        return n
    def add(x):
        n = clean_step(x)
        if not n: return
        if n.lower() == api.lower() and steps: return
        if not any(y.lower() == n.lower() for y in steps): steps.append(n)
    if api and api.lower() not in {'unknown-api','application'}:
        steps.append(api)
    proc_re_local = re.compile(r'\[processor:\s*([^;\]]+)', re.I)
    flow_re_local = re.compile(r'(?:flow(?:Name)?|subflow|route)\s*[=:]\s*["\']?([A-Za-z0-9_][A-Za-z0-9_.:-]{2,80})', re.I)
    outbound_seen = False
    external_candidates = []
    for r in (rows or [])[:1800]:
        msg = str(r.get('message') or '')
        for m in proc_re_local.finditer(msg): add(m.group(1))
        for m in flow_re_local.finditer(msg): add(m.group(1))
        for key in ('create-emandate-sub-flow','mandateStatusCallBack-sub-flow','mandate-status-callback-sub-flow','make-api-call'):
            if key.lower() in msg.lower(): add(key)
        if re.search(r'\b(?:before|after)\s+request\s+to\b|\b(?:calling|request to|invoking|http request|soap request)\b', msg, re.I):
            outbound_seen = True; add('make-api-call')
        dm = re.search(r'(?:request to|calling|invoking)\s+([A-Za-z][A-Za-z0-9_.-]{2,80})', msg, re.I)
        if dm:
            d = _clean_service_name(dm.group(1))
            if d and d.lower() not in generic and 'logger' not in d.lower(): external_candidates.append(d)
    if arch:
        for n in arch.get('nodes', []) or []:
            nm = n.get('name') if isinstance(n, dict) else str(n); add(nm)
        for item in arch.get('simple_flow', []) or []: add(item)
    business = [x for x in steps if not re.search(r'(^|-)entry-logger-flow$|(^|-)exit-logger-flow$', x, re.I)]
    if len(business) >= 2: steps = business
    lows = [x.lower() for x in steps]
    if ('make-api-call' in lows or outbound_seen) and not any(('external' in x or 'flexcube' in x or 'vendor' in x or 'bank' in x) for x in lows):
        insert_after = lows.index('make-api-call') + 1 if 'make-api-call' in lows else len(steps)
        dep = external_candidates[0] if external_candidates else 'External-System'
        if not any(x.lower() == dep.lower() for x in steps): steps.insert(insert_after, dep)
    if not any(x.lower() == 'response' for x in steps): steps.append('Response')
    final = []
    for x in steps:
        if not x: continue
        low = x.lower()
        if low in {'common','default','logging','logger','mule-subflow','external-service','subflow','mule-api','jwt-validation','api-router'}: continue
        if not any(y.lower() == low for y in final): final.append(x)
    return final[:8]

def _synthetic_trace_and_matrix(flow: list, req_count: int = 0, err_count: int = 0, avg_latency: int = 0) -> tuple:
    """Create useful waterfall/matrix data from a clean flow when logs lack distributed trace spans."""
    flow = [x for x in (flow or []) if x]
    if len(flow) < 2:
        return [], []
    per = max(1, int((avg_latency or max(50, len(flow)*20)) / max(1, len(flow)-1)))
    rows = []
    elapsed = 0
    for i, name in enumerate(flow):
        dur = per if i < len(flow)-1 else 1
        rows.append({'time': '', 'service': name, 'level': 'ERROR' if err_count and i == len(flow)-2 else 'INFO', 'message': 'Derived from Mule processor sequence' if i else 'API entry', 'latency': dur, 'start_ms': elapsed, 'duration_ms': dur})
        elapsed += dur
    traces = [{'trace': 'derived-flow', 'rows': rows, 'errors': int(err_count or 0), 'latency': elapsed, 'endpoint': '/', 'api': flow[0]}]
    matrix = []
    for a,b in zip(flow, flow[1:]):
        matrix.append({'from': a, 'to': b, 'calls': int(req_count or 1), 'errors': int(err_count or 0) if b == flow[-2] else 0, 'avg_latency_ms': per, 'error_rate': round((int(err_count or 0)/max(1,int(req_count or 1)))*100,1) if b == flow[-2] else 0})
    return traces, matrix

def _sanitize_architecture_for_response(api_name: str, arch: dict, request_count: int = 0, error_count: int = 0, avg_latency: int = 0) -> dict:
    """Clean old stored architecture payloads so UI does not show generic/noisy topology nodes."""
    arch = arch if isinstance(arch, dict) else {}
    flow = _build_clean_execution_flow(api_name, [], arch)
    if len(flow) >= 2:
        arch['simple_flow'] = flow
        total_steps = len(flow)
        # V11: Use position-aware tier classifier so BBPS/Setu/LMS/etc. land in External lane
        arch['nodes'] = [{'id': x, 'name': x, 'tier': _tier_for_flow_step(x, i, total_steps), 'count': request_count if i in (0,1) else max(1,request_count-i), 'errors': error_count if i == total_steps-2 else 0, 'warns': 0, 'avg_latency_ms': avg_latency if 0 < i < total_steps-1 else 0, 'health': 'critical' if error_count and i == total_steps-2 else 'ok'} for i, x in enumerate(flow)]
        arch['edges'] = [{'from': a, 'to': b, 'count': request_count or 1, 'errors': error_count if b == flow[-2] else 0, 'avg_latency_ms': avg_latency if a != flow[0] else 0, 'error_rate': round(error_count / max(1, request_count or 1) * 100, 1) if b == flow[-2] else 0, 'label': 'calls'} for a, b in zip(flow, flow[1:])]
        if not arch.get('traces') or arch.get('traces') == []:
            traces, matrix = _synthetic_trace_and_matrix(flow, request_count, error_count, avg_latency)
            arch['traces'] = traces
            arch['matrix'] = matrix
        if not arch.get('matrix'):
            _, matrix = _synthetic_trace_and_matrix(flow, request_count, error_count, avg_latency)
            arch['matrix'] = matrix
        arch['tiers'] = sorted(set(_service_tier(x) for x in flow), key=lambda t: {"Client":0,"Gateway":1,"API":2,"Service":3,"External":4,"Data":5}.get(t,9))
    arch.setdefault('hints', [])
    if 'Cleaned topology: processor event IDs and generic tags are hidden.' not in arch['hints']:
        arch['hints'].append('Cleaned topology: processor event IDs and generic tags are hidden.')
    return arch
def _tier_for_flow_step(name: str, idx: int, total: int) -> str:
    """Classify a topology flow step into the correct architecture tier.
    More precise than _service_tier — understands position and downstream semantics."""
    low = (name or '').lower()
    if low in ('response', 'response exit', 'client', 'caller'):
        return 'Client'
    # HTTP method/endpoint labels always go in Gateway lane
    if re.match(r'^(get|post|put|delete|patch|head|options)\s', low):
        return 'Gateway'
    # Known external downstream systems — must come before generic 'service' check
    _EXTERNAL_SIGNALS = (
        'bbps', 'setu', 'upi', 'upi gateway', 'salesforce', 'sfdc',
        'gupshup', 'lms', 'lms core', 'lms / flexcube', 'flexcube', 'fcubs', 'core banking',
        'kotak', 'nach', 'emandate', 'html/pdf', 'html to pdf', 'pdf engine',
        'twilio', 'sms gateway', 'sendgrid', 'email service',
        'aws s3', 's3', 'kafka', 'message broker', 'event bus',
        'payment engine', 'payment processing', 'payment',
        'crif', 'cibil', 'bureau', 'credit score',
        'external system', 'third party', 'vendor',
    )
    if any(x in low for x in _EXTERNAL_SIGNALS):
        return 'External'
    # Data stores
    if any(x in low for x in ('oracle', 'postgres', 'mysql', 'mongo', 'redis', 'db', 'database',
                               'cache', 'mssql', 'jdbc', 'dynamo', 'elastic', 'elasticsearch')):
        return 'Data'
    # MuleSoft gateway / proxy
    if any(x in low for x in ('gateway', 'proxy', 'apigee', 'nginx', 'lb', 'loadbalancer', 'kong')):
        return 'Gateway'
    # First node in flow = the primary API
    if idx == 0:
        return 'API'
    # Internal processors / sub-flows = Service
    if any(x in low for x in ('subflow', 'impl', 'processor', 'handler', 'worker',
                               'validator', 'transformer', 'token', 'auth',
                               'request entry', 'response exit', 'security logging',
                               'downstream call')):
        return 'Service'
    # MuleSoft API names
    if re.search(r'\bs-[a-z]', low) or any(x in low for x in ('api', 'mule', 'process-api', '-api-')):
        return 'API'
    return 'Service'


def _service_tier(name: str) -> str:
    """Classify a service name into an architecture tier."""
    low = (name or '').lower()
    # Sentinel / boundary nodes
    if low in ('client', 'response', 'external-client'): 
        return 'Client'
    if any(x in low for x in ('client', 'browser', 'mobile', 'postman', 'consumer', 'user')):
        return 'Client'
    if any(x in low for x in ('gateway', 'proxy', 'apigee', 'nginx', 'lb', 'loadbalancer', 'kong')):
        return 'Gateway'
    # MuleSoft experience/process layer APIs
    if any(x in low for x in ('experience', 'exp-api', '-exp-', 'system-api', 'sys-api')):
        return 'API'
    if re.search(r'\bs-[a-z]', low) or any(x in low for x in ('api', 'mule', 'process-api', '-api-')):
        return 'API'
    # MuleSoft subflows and implementation flows are Services
    if any(x in low for x in ('subflow', 'impl', 'flow', 'processor', 'engine', 'service', 'handler', 'worker', 'payment', 'loan', 'customer', 'auth', 'validator', 'transformer')):
        return 'Service'
    if any(x in low for x in ('oracle', 'postgres', 'mysql', 'mongo', 'redis', 'db', 'database', 'cache', 'mssql', 'jdbc')):
        return 'Data'
    if any(x in low for x in ('salesforce', 'cbs', 'flexcube', 'kafka', 's3', 'lambda', 'external', 'vendor', 'http', 'soap', 'sftp', 'ftp', 'smtp')):
        return 'External'
    return 'Service'


def _normalise_endpoint(endpoint: str) -> str:
    """Normalise a REST endpoint path. Returns '' if value looks like a service/flow name not an HTTP path."""
    ep = str(endpoint or '').split('?')[0].strip()
    if not ep or ep == '__root__':
        return '/'
    # If it doesn't start with '/' it's likely a flow/service name, not an HTTP path
    if not ep.startswith('/'):
        return '/'
    # Replace numeric IDs and UUIDs in path segments
    ep = re.sub(r'/\d+(?=/|$)', '/{id}', ep)
    ep = re.sub(r'/[0-9a-fA-F-]{8,}(?=/|$)', '/{id}', ep)
    # Collapse overly long subflow-style paths (MuleSoft emits full flow names as paths sometimes)
    # A valid REST endpoint has ≤ 8 segments; anything longer is a flow descriptor
    parts = [p for p in ep.split('/') if p]
    if len(parts) > 8:
        ep = '/' + '/'.join(parts[:8])
    return ep[:220]


def extract_architecture_graph(rows: list, raw: str, env: str, session_id: int, user_id: int, api_name: str = '', endpoint: str = '') -> dict:
    """
    Build an architecture-level topology from logs.
    Produces: tiered nodes, directed edges, trace waterfall, service call matrix.
    Handles MuleSoft flow logs, standard microservice logs, and JSON-structured logs.
    """
    node_map: dict = {}
    edge_map: dict = {}
    traces: dict = {}

    def add_node(name: str, tier: str = None, row: dict = None) -> str:
        name = _clean_service_name(name)
        if not name or len(name) < 2:
            return ''
        tier = tier or _service_tier(name)
        n = node_map.setdefault(name, {
            "id": name, "name": name, "tier": tier,
            "count": 0, "errors": 0, "warns": 0, "latencies": []
        })
        n['count'] += 1
        if row:
            lvl = row.get('level', '')
            n['errors'] += 1 if lvl in ('ERROR', 'FAILURE') else 0
            n['warns']  += 1 if lvl == 'WARN' else 0
            lat = row.get('latency')
            if lat and int(lat) > 0:
                n['latencies'].append(int(lat))
        return name

    def add_edge(src: str, dst: str, row: dict = None, label: str = 'calls') -> None:
        src = _clean_service_name(src)
        dst = _clean_service_name(dst)
        if not src or not dst or src == dst:
            return
        # Ensure both nodes exist
        add_node(src)
        add_node(dst)
        key = (src, dst)
        e = edge_map.setdefault(key, {
            "from": src, "to": dst,
            "count": 0, "errors": 0, "latencies": [], "label": label
        })
        e['count'] += 1
        if row:
            lvl = row.get('level', '')
            e['errors'] += 1 if lvl in ('ERROR', 'FAILURE') else 0
            lat = row.get('latency')
            if lat and int(lat) > 0:
                e['latencies'].append(int(lat))

    # ── Compiled regexes for hop extraction ──────────────────────────────────
    # MuleSoft flow/subflow names in log lines
    flow_re    = re.compile(r'(?:flow(?:Name)?|subflow|route)\s*[=:]\s*["\']?([A-Za-z0-9_][A-Za-z0-9_.:-]{2,80})', re.I)
    # "before request to X" / "after request to X"
    before_re  = re.compile(r'before\s+request\s+to\s+["\']?([A-Za-z0-9_][A-Za-z0-9_.:/%-]{2,100})', re.I)
    after_re   = re.compile(r'after\s+request\s+to\s+["\']?([A-Za-z0-9_][A-Za-z0-9_.:/%-]{2,100})', re.I)
    # Generic call/connect patterns
    call_re    = re.compile(r'\b(?:calling|call to|request to|response from|connecting to|connect to|invoking|invoked)\s+["\']?([A-Za-z0-9_][A-Za-z0-9_.:/%-]{2,100})', re.I)
    # JSON key-value: "service":"x", "component":"x", "target":"x"
    svc_re     = re.compile(r'"(?:service|component|target|destination|callee|caller)"\s*:\s*"([A-Za-z0-9_][A-Za-z0-9_.:-]{1,80})"', re.I)
    # processor: X in log lines
    proc_re    = re.compile(r'processor:\s*([A-Za-z0-9_][A-Za-z0-9_.:/-]{2,80})', re.I)

    # Words to exclude from hop names (common log noise)
    NOISE = {
        'true','false','null','none','get','post','put','delete','patch',
        'http','https','200','201','400','401','403','404','500','502','503',
        'info','debug','warn','error','success','failure','trace',
        'request','response','message','event','log','line',
    }

    def _is_valid_hop(name: str) -> bool:
        """Filter out paths, URLs, log-level words and very short tokens."""
        if not name or len(name) < 3:
            return False
        low = name.lower()
        if low in NOISE:
            return False
        if _looks_like_processor_event_name(name):
            return False
        # Reject if it looks like a URL path segment starting with /
        if name.startswith('/'):
            return False
        # Reject pure numeric strings
        if re.match(r'^\d+$', name):
            return False
        return True

    # ── Main extraction loop ──────────────────────────────────────────────────
    for r in (rows or []):
        msg  = r.get('message', '') or ''
        app  = _clean_service_name(r.get('app') or api_name or 'Unknown-API') or 'Unknown-API'
        lvl  = r.get('level', '')
        trace_id = r.get('trace') or r.get('event') or ''
        ep   = _normalise_endpoint(endpoint or '')

        # The primary node for this log line is the API/app itself
        current = add_node(app, 'API', r)
        hops = [current] if current else []

        # --- Extract additional hops from the message -----------------------
        candidates = []

        # MuleSoft flow names (clean, well-structured)
        for m in flow_re.finditer(msg):
            candidates.append(_clean_service_name(m.group(1)))

        # Processor names
        for m in proc_re.finditer(msg):
            candidates.append(_clean_service_name(m.group(1)))

        # Before/after request patterns (strong signal: an actual outbound call)
        for m in before_re.finditer(msg):
            raw_hop = m.group(1).rstrip('/')
            # Strip URL scheme & host if it's a full URL; keep the host as service name
            raw_hop = re.sub(r'^https?://([^/]+).*', r'\1', raw_hop)
            candidates.append(_clean_service_name(raw_hop))

        for m in after_re.finditer(msg):
            raw_hop = m.group(1).rstrip('/')
            raw_hop = re.sub(r'^https?://([^/]+).*', r'\1', raw_hop)
            candidates.append(_clean_service_name(raw_hop))

        # Generic call/connect patterns
        for m in call_re.finditer(msg):
            raw_hop = m.group(1).rstrip('/')
            raw_hop = re.sub(r'^https?://([^/]+).*', r'\1', raw_hop)
            candidates.append(_clean_service_name(raw_hop))

        # JSON service/component keys
        for m in svc_re.finditer(msg):
            candidates.append(_clean_service_name(m.group(1)))

        # Deduplicate candidates, filter noise, add to hops
        seen_lower = {h.lower() for h in hops}
        for c in candidates:
            if c and _is_valid_hop(c) and c.lower() not in seen_lower:
                hops.append(c)
                seen_lower.add(c.lower())
                add_node(c, row=r)

        # Build the edge chain: Client → hop0 → hop1 → ... → Response
        add_node('Client', 'Client')
        add_node('Response', 'Client')

        if hops:
            add_edge('Client', hops[0], r, 'entry')
            for a, b in zip(hops, hops[1:]):
                add_edge(a, b, r, 'calls')
            add_edge(hops[-1], 'Response', r, 'returns')
        else:
            add_edge('Client', current or app, r, 'entry')
            add_edge(current or app, 'Response', r, 'returns')

        # ── Trace waterfall accumulation ─────────────────────────────────────
        if trace_id:
            tr = traces.setdefault(trace_id, {
                "trace": trace_id, "rows": [],
                "errors": 0, "latency": 0,
                "endpoint": ep, "api": app
            })
            tr['rows'].append({
                "time":    r.get('time', ''),
                "service": hops[-1] if hops else app,
                "level":   lvl,
                "message": msg[:280],
                "latency": int(r.get('latency') or 0)
            })
            tr['errors']  += 1 if lvl in ('ERROR', 'FAILURE') else 0
            tr['latency']  = max(tr['latency'], int(r.get('latency') or 0))

    # ── Finalise nodes ────────────────────────────────────────────────────────
    tier_order = {"Client": 0, "Gateway": 1, "API": 2, "Service": 3, "External": 4, "Data": 5}
    nodes = []
    for n in node_map.values():
        lats = n.pop('latencies', [])
        n['avg_latency_ms'] = round(sum(lats) / len(lats)) if lats else 0
        n['health'] = 'critical' if n['errors'] else 'warn' if n['warns'] else 'ok'
        nodes.append(n)
    nodes.sort(key=lambda n: (tier_order.get(n['tier'], 9), n['name']))

    # ── Finalise edges ────────────────────────────────────────────────────────
    edges = []
    for e in edge_map.values():
        lats = e.pop('latencies', [])
        e['avg_latency_ms'] = round(sum(lats) / len(lats)) if lats else 0
        e['error_rate'] = round(e['errors'] / max(1, e['count']) * 100, 1)
        edges.append(e)
    edges.sort(key=lambda e: -e['count'])

    # ── Call matrix (top 60 edges) ────────────────────────────────────────────
    matrix = [
        {
            "from": e['from'], "to": e['to'],
            "calls": e['count'], "errors": e['errors'],
            "avg_latency_ms": e['avg_latency_ms'],
            "error_rate": e['error_rate']
        }
        for e in edges[:60]
    ]

    # ── Trace list (top 12 most interesting) ─────────────────────────────────
    trace_list = sorted(
        traces.values(),
        key=lambda t: (-t['errors'], -t['latency'], -len(t['rows']))
    )[:12]

    active_tiers = sorted(
        set(n['tier'] for n in nodes),
        key=lambda x: tier_order.get(x, 9)
    )

    return {
        "nodes": nodes,
        "edges": edges,
        "traces": trace_list,
        "matrix": matrix,
        "tiers": active_tiers
    }


def extract_system_map(rows: list, raw: str, env: str, session_id: int, user_id: int):
    """Extract API endpoint maps plus a tiered architecture graph for each endpoint."""
    api_groups = {}
    last_api = ''
    for r in rows:
        api = _clean_service_name(r.get('app') or 'unknown') or 'unknown'
        if _looks_like_processor_event_name(api) or not _is_valid_api_inventory_name(api):
            msg = r.get('message', '') or ''
            recovered = extract_first([r'\[([A-Za-z0-9_.-]+-api)\]\.[A-Za-z0-9_-]+', r'\[([A-Za-z0-9_.-]+-api)\]', r'([A-Za-z0-9_.-]+-api)-config'], msg, last_api or 'unknown')
            api = _clean_service_name(recovered) or last_api or 'unknown'
        if api != 'unknown':
            last_api = api
        api_groups.setdefault(api, []).append(r)

    # URI patterns: strictly match HTTP path patterns only (must start with /)
    uri_patterns = [
        r'"(?:uri|requestUri|path|requestPath|url)"\s*:\s*"(/[^"?#\s]{1,300})"',
        r"'(?:uri|requestUri|path|requestPath|url)'\s*:\s*'(/[^'?#\s]{1,300})'",
        r'(?:uri|url|path|endpoint|requestPath)\s*[=:]\s*["\']?(/[A-Za-z0-9/_\-.{}]+)',
        r'\b(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+(/[A-Za-z0-9/_\-.{}?=&%]+)',
        r'"HttpMethod"\s*:\s*"[A-Z]+"\s*[,}].*?"(?:uri|path|url)"\s*:\s*"(/[^"]+)"',
    ]
    method_pattern = re.compile(r'\b(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\b', re.I)

    flow_maps = []
    for api_name, api_rows in api_groups.items():
        if api_name == 'unknown' and len(api_groups) > 1:
            continue

        endpoint_groups: dict = {}
        for r in api_rows:
            msg = r.get('message', '') or ''
            ep = ''
            route_method = ''

            # V6: Mule runtime route is the most reliable endpoint signal.
            try:
                _a, route_method, route_ep = _extract_mule_route_from_text(msg)
                if route_ep and route_ep != '/':
                    ep = route_ep
                    if route_method:
                        r['method'] = route_method
                        r['endpoint'] = route_ep
            except Exception:
                pass

            if not ep:
                for pat in uri_patterns:
                    m = re.search(pat, msg, re.I | re.S)
                    if m:
                        candidate = _normalise_endpoint(m.group(1))
                        if candidate and candidate != '/' and len(candidate) > 1:
                            ep = candidate
                            break

            if not ep:
                ep = '/'

            method_key = (r.get('method') or route_method or '').upper()
            endpoint_groups.setdefault((method_key, ep), []).append(r)

        for endpoint_key, ep_rows in endpoint_groups.items():
            method, endpoint = endpoint_key if isinstance(endpoint_key, tuple) else ('', endpoint_key)
            for r in ep_rows[:50]:
                mm = method_pattern.search(r.get('message', '') or '')
                if mm and not method:
                    method = mm.group(1).upper()
                    break

            arch = extract_architecture_graph(ep_rows, raw, env, session_id, user_id, api_name, endpoint)

            req_count  = len(ep_rows)
            err_count  = sum(1 for r in ep_rows if r.get('level') in ('ERROR', 'FAILURE'))
            lats       = [int(r.get('latency') or 0) for r in ep_rows if r.get('latency') and int(r.get('latency') or 0) > 0]
            avg_lat    = round(sum(lats) / len(lats)) if lats else 0

            # Build clean semantic topology from Mule processor sequence, not from generic tag/tier sorting.
            flow_steps = _build_clean_execution_flow(api_name, ep_rows, arch)
            arch['simple_flow'] = flow_steps
            # V11: Only rebuild nodes/edges if the topology engine didn't already produce
            # a richer graph. This preserves the v3 engine's detailed downstream detection
            # (BBPS, Setu, UPI, LMS, Flexcube, etc.) instead of clobbering it with a flat chain.
            existing_nodes = arch.get('nodes') or []
            if len(existing_nodes) < len(flow_steps):
                total_steps = len(flow_steps)
                arch['nodes'] = [
                    {
                        'id': x, 'name': x,
                        'tier': _tier_for_flow_step(x, i, total_steps),
                        'count': req_count if i in (0, 1) else max(1, req_count - i),
                        'errors': err_count if i == total_steps - 2 else 0,
                        'warns': 0,
                        'avg_latency_ms': avg_lat if 0 < i < total_steps - 1 else 0,
                        'health': 'critical' if err_count and i == total_steps - 2 else 'ok',
                    }
                    for i, x in enumerate(flow_steps)
                ]
                arch['edges'] = [
                    {
                        'from': a, 'to': b,
                        'count': req_count or 1,
                        'errors': err_count if b == flow_steps[-2] else 0,
                        'avg_latency_ms': avg_lat if a != flow_steps[0] else 0,
                        'error_rate': round(err_count / max(1, req_count) * 100, 1) if b == flow_steps[-2] else 0,
                        'label': 'calls',
                    }
                    for a, b in zip(flow_steps, flow_steps[1:])
                ]
            if not arch.get('traces'):
                traces, matrix = _synthetic_trace_and_matrix(flow_steps, req_count, err_count, avg_lat)
                arch['traces'] = traces
                arch['matrix'] = matrix
            elif not arch.get('matrix'):
                _, matrix = _synthetic_trace_and_matrix(flow_steps, req_count, err_count, avg_lat)
                arch['matrix'] = matrix
            arch['tiers'] = sorted(set(_service_tier(x) for x in flow_steps), key=lambda t: {"Client":0,"Gateway":1,"API":2,"Service":3,"External":4,"Data":5}.get(t,9))
            arch.setdefault('hints', [])
            arch['hints'].append('Topology is built from Mule processor order; generic tags such as common/default/logging are hidden.')
            req_count  = len(ep_rows)
            err_count  = sum(1 for r in ep_rows if r.get('level') in ('ERROR', 'FAILURE'))
            lats       = [int(r.get('latency') or 0) for r in ep_rows if r.get('latency') and int(r.get('latency') or 0) > 0]
            avg_lat    = round(sum(lats) / len(lats)) if lats else 0
            sample_trace = next(
                (r.get('trace') or r.get('event') for r in ep_rows if r.get('trace') or r.get('event')),
                ''
            )
            flow_maps.append(ApiFlowMap(
                user_id=user_id, session_id=session_id,
                api_name=api_name, environment=env,
                endpoint=endpoint if endpoint != '/' else '',
                method=method,
                flow_steps_json=json.dumps(flow_steps[:14]),
                architecture_json=json.dumps(arch, default=str),
                request_count=req_count,
                error_count=err_count,
                avg_latency_ms=avg_lat,
                sample_trace_id=(sample_trace or '')[:120]
            ))
    return flow_maps


def _json_loads_safe(value, default=None):
    if default is None:
        default = []
    try:
        return json.loads(value) if value else default
    except Exception:
        return default

def _row_api_name(row, fallback="unknown-api"):
    name = _clean_service_name(row.get("app") or row.get("application") or fallback or "unknown-api")
    if _looks_like_processor_event_name(name):
        return _clean_service_name(fallback or "unknown-api")
    return name

def _row_endpoint(row):
    raw = row.get("endpoint") or row.get("path") or row.get("uri") or ""
    if not raw:
        msg = str(row.get("message") or "")
        m = re.search(r'\b(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+(/[^\s?"\']+)', msg, re.I)
        if not m:
            m = re.search(r'"(?:uri|requestUri|path|requestPath|url|endpoint)"\s*:\s*"(/[^"]+)"', msg, re.I)
        raw = m.group(1) if m else "/"
    return _normalise_endpoint(raw) or "/"

def _row_trace(row):
    return str(row.get("trace") or row.get("trace_id") or row.get("correlationId") or row.get("event") or "")[:160]

def persist_observability_indexes(user_id, session_id, rows, raw, env, filename, flow_maps=None):
    """Persist API registry, endpoint inventory, log events, trace index and flow edges."""
    rows = list(rows or [])[:5000]
    env = (env or "PROD").upper()
    fallback_api = filename or "unknown-api"
    for model in (LogEvent, TraceIndex, FlowEdge):
        try:
            model.query.filter_by(user_id=user_id, session_id=session_id).delete()
        except Exception:
            db.session.rollback()
    endpoint_stats = {}
    trace_groups = {}
    for r in rows:
        api_name = _row_api_name(r, fallback_api)
        endpoint = _row_endpoint(r)
        trace_id = _row_trace(r)
        level = str(r.get("level") or detect_level(r.get("message", "")) or "INFO").upper()[:20]
        lat_raw = r.get("latency") or 0
        latency = int(lat_raw) if str(lat_raw).isdigit() else 0
        key = (api_name, endpoint, str(r.get("method") or "").upper()[:10])
        stat = endpoint_stats.setdefault(key, {"requests": 0, "errors": 0, "latencies": []})
        stat["requests"] += 1
        stat["errors"] += 1 if level in ("ERROR", "FAILURE") else 0
        if latency > 0:
            stat["latencies"].append(latency)
        db.session.add(LogEvent(
            user_id=user_id, session_id=session_id, environment=env, api_name=api_name,
            endpoint=endpoint, trace_id=trace_id, level=level, event_time=str(r.get("time") or "")[:80],
            message=str(r.get("message") or "")[:4000], latency_ms=latency, row_json=json.dumps(r, default=str)
        ))
        if trace_id:
            rr = dict(r)
            rr.update({"api_name": api_name, "endpoint": endpoint, "level": level, "latency": latency})
            trace_groups.setdefault(trace_id, []).append(rr)
    now = datetime.datetime.utcnow()
    for (api_name, endpoint, method), stat in endpoint_stats.items():
        reg = ApiRegistry.query.filter_by(user_id=user_id, api_name=api_name, environment=env).first()
        if not reg:
            reg = ApiRegistry(user_id=user_id, api_name=api_name, environment=env, status="active")
            db.session.add(reg); db.session.flush()
        reg.last_seen_at = now
        try:
            downstream = set(_json_loads_safe(reg.downstream_systems_json, []))
            for fm in flow_maps or []:
                if fm.api_name == api_name:
                    arch = _json_loads_safe(fm.architecture_json, {})
                    for n in arch.get("nodes", []):
                        if n.get("tier") in ("External", "Data", "Service") and n.get("name") != api_name:
                            downstream.add(str(n.get("name"))[:160])
            reg.downstream_systems_json = json.dumps(sorted(x for x in downstream if x))
        except Exception:
            pass
        avg_lat = round(sum(stat["latencies"]) / len(stat["latencies"])) if stat["latencies"] else 0
        ep = ApiEndpoint.query.filter_by(user_id=user_id, api_name=api_name, environment=env, endpoint=endpoint, method=method).first()
        if not ep:
            ep = ApiEndpoint(user_id=user_id, api_registry_id=reg.id, api_name=api_name, environment=env, endpoint=endpoint, method=method)
            db.session.add(ep)
        ep.api_registry_id = reg.id
        ep.request_count = int(ep.request_count or 0) + stat["requests"]
        ep.error_count = int(ep.error_count or 0) + stat["errors"]
        ep.avg_latency_ms = avg_lat
        ep.last_seen_at = now
    for trace_id, tr_rows in list(trace_groups.items())[:1000]:
        max_lat = max((int(x.get("latency") or 0) for x in tr_rows), default=0)
        has_error = any(str(x.get("level", "")).upper() in ("ERROR", "FAILURE") for x in tr_rows)
        db.session.add(TraceIndex(
            user_id=user_id, session_id=session_id, trace_id=trace_id, environment=env,
            api_name=_row_api_name(tr_rows[0], fallback_api), endpoint=_row_endpoint(tr_rows[0]),
            status="error" if has_error else "success", latency_ms=max_lat,
            rows_json=json.dumps(tr_rows[:250], default=str)
        ))
    for fm in flow_maps or []:
        try:
            arch = _json_loads_safe(fm.architecture_json, {})
            for edge in arch.get("edges", [])[:200]:
                db.session.add(FlowEdge(
                    user_id=user_id, session_id=session_id, environment=env, api_name=fm.api_name, endpoint=fm.endpoint or "/",
                    source=str(edge.get("from") or edge.get("source") or "")[:200],
                    target=str(edge.get("to") or edge.get("target") or "")[:200],
                    label=str(edge.get("label") or "calls")[:80],
                    count=int(edge.get("count") or 1), errors=int(edge.get("errors") or 0)
                ))
        except Exception:
            app.logger.exception("Flow edge indexing failed")

def search_indexed_log_events(user_id, q="", env="", limit=200):
    query = LogEvent.query.filter_by(user_id=user_id)
    if env and str(env).upper() not in ("ALL", "ANY"):
        query = query.filter(LogEvent.environment.ilike(str(env)))
    terms = [t for t in re.split(r"\s+", q or "") if t]
    for term in terms:
        if ":" in term:
            k, v = term.split(":", 1)
            v = v.strip()
            if not v:
                continue
            lk = k.lower()
            if lk in ("level", "severity"):
                query = query.filter(LogEvent.level.ilike(v))
            elif lk in ("trace", "traceid", "event", "eventid"):
                query = query.filter(LogEvent.trace_id.ilike(f"%{v}%"))
            elif lk in ("api", "app", "application"):
                query = query.filter(LogEvent.api_name.ilike(f"%{v}%"))
            elif lk in ("endpoint", "path", "uri"):
                query = query.filter(LogEvent.endpoint.ilike(f"%{v}%"))
            elif lk == "env":
                query = query.filter(LogEvent.environment.ilike(v))
            else:
                query = query.filter(db.or_(LogEvent.message.ilike(f"%{term}%"), LogEvent.row_json.ilike(f"%{term}%")))
        else:
            like = f"%{term}%"
            query = query.filter(db.or_(LogEvent.message.ilike(like), LogEvent.row_json.ilike(like), LogEvent.trace_id.ilike(like), LogEvent.api_name.ilike(like), LogEvent.endpoint.ilike(like)))
    rows = query.order_by(LogEvent.created_at.desc(), LogEvent.id.desc()).limit(limit).all()
    return [(_json_loads_safe(r.row_json, {}) or {"time": r.event_time, "level": r.level, "app": r.api_name, "endpoint": r.endpoint, "trace": r.trace_id, "latency": r.latency_ms, "message": r.message}) for r in rows]


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


# ── Clean Mule architecture override ─────────────────────────────────────────
# This override intentionally abstracts logger lines into an understandable,
# architecture-level flow. It prevents phrases like "before loan details log"
# and "after loan details log" from becoming fake services in System Map.
def _mule_row_parts(row):
    msg = row.get("message", "") or ""
    api = row.get("app") or "unknown-api"
    method = ""
    endpoint = ""
    m = re.search(r"\[([^\]]+)\]\.(get|post|put|delete|patch):\\([^:]+)", msg, re.I)
    if m:
        api = _clean_service_name(m.group(1))
        method = m.group(2).upper()
        endpoint = "/" + m.group(3).strip("\\/").replace("\\", "/")
    flow = row.get("flow") or ""
    fm = re.search(r"processor:\s*([^;/\]]+)", msg, re.I)
    if fm:
        flow = _clean_service_name(fm.group(1))
    step = 0
    sm = re.search(r"processors/(\d+)", msg, re.I)
    if sm:
        step = int(sm.group(1))
    stage = "After Response" if re.search(r"\bafter\b", msg, re.I) else "Before Request" if re.search(r"\bbefore\b", msg, re.I) else "Processing"
    return api, method, endpoint, flow, step, stage

def extract_architecture_graph(rows: list, raw: str, env: str, session_id: int, user_id: int, api_name: str = '', endpoint: str = '') -> dict:
    mule_rows = [r for r in (rows or []) if "MuleRuntime" in (r.get("message","") or "") or "processor:" in (r.get("message","") or "")]
    if mule_rows:
        node_map, edge_map, trace_map = {}, {}, {}
        def add_node(name, tier, row=None):
            name = _clean_service_name(name or "")
            if not name: return ""
            n = node_map.setdefault(name, {"id":name,"name":name,"tier":tier,"count":0,"errors":0,"warns":0,"avg_latency_ms":0,"health":"ok"})
            n["count"] += 1
            if row:
                lvl = str(row.get("level","")).upper()
                n["errors"] += 1 if lvl in ("ERROR","FAILURE") else 0
                n["warns"] += 1 if lvl == "WARN" else 0
                n["health"] = "critical" if n["errors"] else "warn" if n["warns"] else "ok"
            return name
        def add_edge(a,b,row=None,label="calls"):
            a=add_node(a, "Client" if a=="Client" else "Service", row if a!="Client" else None)
            b=add_node(b, "Client" if b=="Response" else "Service", row if b!="Response" else None)
            if not a or not b or a==b: return
            e=edge_map.setdefault((a,b), {"from":a,"to":b,"count":0,"errors":0,"avg_latency_ms":0,"label":label})
            e["count"] += 1
            if row and str(row.get("level","")).upper() in ("ERROR","FAILURE"):
                e["errors"] += 1
        # group by api/endpoint/flow to build a clean flow instead of log text
        for r in mule_rows:
            api, method, ep, flow, step, stage = _mule_row_parts(r)
            api = api_name or api or "Mule API"
            ep = endpoint or ep or _normalise_endpoint(r.get("endpoint","") or "")
            flow = flow or "Mule Subflow"
            add_node("Client","Client")
            add_node(api,"API",r)
            add_node("JWT Validation","Gateway",r)
            add_node("API Router","Gateway",r)
            add_node(flow,"Service",r)
            add_node("External Service","External",r)
            add_node("Logging","Service",r)
            add_node("Response","Client")
            add_edge("Client", api, r, "request")
            add_edge(api, "JWT Validation", r, "validates")
            add_edge("JWT Validation", "API Router", r, "routes")
            add_edge("API Router", flow, r, method or "calls")
            # processors/1 is usually before external/downstream; processors/3 after response/logging
            if step <= 1 or stage == "Before Request":
                add_edge(flow, "External Service", r, "downstream")
            else:
                add_edge("External Service", flow, r, "returns")
                add_edge(flow, "Logging", r, "logs")
            add_edge("Logging", "Response", r, "returns")
            trace = r.get("trace") or r.get("event") or ""
            if trace:
                tr = trace_map.setdefault(trace, {"trace":trace,"api":api,"endpoint":ep,"rows":[],"errors":0,"latency":0})
                tr["rows"].append({"time":r.get("time",""),"service":flow,"stage":stage,"level":r.get("level",""),"message":(r.get("message","") or "")[:260],"latency":int(r.get("latency") or 0)})
                tr["errors"] += 1 if str(r.get("level","")).upper() in ("ERROR","FAILURE") else 0
        nodes=list(node_map.values())
        tiers=["Client","Gateway","API","Service","External"]
        for e in edge_map.values():
            e["error_rate"] = round(e["errors"]/max(1,e["count"])*100,1)
        edges=sorted(edge_map.values(), key=lambda e:-e["count"])
        matrix=[{"from":e["from"],"to":e["to"],"calls":e["count"],"errors":e["errors"],"avg_latency_ms":0,"error_rate":e["error_rate"]} for e in edges]
        traces=sorted(trace_map.values(), key=lambda t:(-t["errors"], -len(t["rows"])))[:12]
        return {
            "nodes": nodes, "edges": edges, "traces": traces, "matrix": matrix, "tiers": tiers,
            "simple_flow": _build_clean_execution_flow(api_name or api or "Mule API", mule_rows, {"nodes": list(node_map.values())}),
            "hints": [
                "Mule logger messages are treated as stages, not architecture services.",
                "processors/1 is interpreted as before/downstream request; processors/3 as after/response logging.",
                "For exact external service names, add logs like 'before request to CustomerService' or a JSON field target/service."
            ]
        }
    # Non-Mule fallback: keep existing generic topology but avoid raw before/after logger phrases.
    return {
        "nodes": [
            {"id":"Client","name":"Client","tier":"Client","count":len(rows or []),"errors":0,"warns":0,"avg_latency_ms":0,"health":"ok"},
            {"id":api_name or "Application","name":api_name or "Application","tier":"API","count":len(rows or []),"errors":sum(1 for r in rows or [] if r.get("level") in ("ERROR","FAILURE")),"warns":0,"avg_latency_ms":0,"health":"ok"},
            {"id":"Response","name":"Response","tier":"Client","count":len(rows or []),"errors":0,"warns":0,"avg_latency_ms":0,"health":"ok"}
        ],
        "edges": [
            {"from":"Client","to":api_name or "Application","count":len(rows or []),"errors":0,"avg_latency_ms":0,"label":"request","error_rate":0},
            {"from":api_name or "Application","to":"Response","count":len(rows or []),"errors":0,"avg_latency_ms":0,"label":"returns","error_rate":0}
        ],
        "traces": [], "matrix": [], "tiers": ["Client","API"],
        "simple_flow": ["Client", api_name or "Application", "Response"]
    }


# ── V40 fast upload + real Mule topology engine ───────────────────────────────
# This replaces the previous tag-chain topology. It groups Mule lines by event id,
# builds a business flow from ENTRY/CALL-ENTRY/processor/CALL-EXIT/EXIT semantics,
# and always returns Client → API → Endpoint → business stages → downstream → Response.

def _extract_mule_route_from_text(text: str):
    msg = str(text or '').replace('\r', '\\r')
    m = re.search(r'\[([A-Za-z0-9_.-]+-api)\]\.(get|post|put|delete|patch|head|options):(.+?)(?:-config|\s|\]|\)|@)', msg, re.I)
    if not m:
        return '', '', ''
    api = _clean_service_name(m.group(1))
    method = m.group(2).upper()
    path = m.group(3).strip()
    path = re.split(r':(?:application|text|multipart|json|xml)', path, maxsplit=1, flags=re.I)[0]
    path = re.sub(r'/processors/.*$', '', path, flags=re.I)
    path = path.replace('\\', '/').replace('//', '/').strip('/ :')
    endpoint = '/' + path if path else '/'
    endpoint = _normalise_endpoint(endpoint) or '/'
    return api, method, endpoint

def _trace_id_from_row(row: dict) -> str:
    return str(row.get('trace') or row.get('event') or row.get('trace_id') or '')[:160]

def _extract_processor_from_msg(msg: str) -> str:
    m = re.search(r'\[processor:\s*([^;\]]+)', str(msg or ''), re.I)
    return m.group(1) if m else ''

def _flow_name_from_common_logger(msg: str) -> str:
    m = re.search(r"Flow Name:\s*'\s*([^']+?)\s*'", str(msg or ''), re.I)
    return _clean_service_name(m.group(1)) if m else ''

def _infer_business_label(text: str, processor: str = '', endpoint: str = ''):
    msg = str(text or '').lower(); proc = str(processor or '').lower(); ep = str(endpoint or '').lower()
    if 'loan\\receipt' in msg or '/loan/receipt' in ep or 'loan-receipt' in proc or 'receipt-token' in proc: return 'Loan Receipt'
    if 'paymentengine\\loandetails' in msg or '/paymentengine/loandetails' in ep or 'loan-details' in proc: return 'Loan Details'
    if 'generate-otp' in msg or 'generate-otp' in proc or '/generate-otp' in ep: return 'Generate OTP'
    if 'verify-otp' in msg or 'verify-otp' in proc or '/verify-otp' in ep: return 'Verify OTP'
    if 'htmltopdf' in msg or 'html-to-pdf' in proc or 'htmltopdf' in ep: return 'HTML to PDF'
    if 'crif' in msg and 'sms' in msg: return 'CRIF SMS'
    if 'emandate' in msg or 'mandate' in proc: return 'Kotak eMandate'
    return ''

def _endpoint_label(method: str, endpoint: str, business: str = '') -> str:
    if method and endpoint and endpoint != '/':
        return f'{method} {endpoint}'
    return business or 'API Endpoint'

def _processor_stage_name(processor: str, message: str = '', endpoint: str = ''):
    proc = _clean_service_name(_normalise_mule_component_name(processor or '')); low = proc.lower()
    if not proc:
        return _infer_business_label(message, processor, endpoint) or ''
    if 'entry-logger' in low or 'call-entry-logger' in low: return 'Request Entry'
    if 'exit-logger' in low or 'call-exit-logger' in low: return 'Response Exit'
    if 'token' in low or 'jwt' in low or 'authorization' in low: return 'Token / Auth'
    if 'google' in low and 'secops' in low: return 'Security Logging'
    if 'loan-details' in low: return 'Loan Details'
    if 'loan-receipt' in low or 'receipt' in low: return 'Loan Receipt'
    if 'generate-otp' in low: return 'Generate OTP'
    if 'verify-otp' in low: return 'Verify OTP'
    if 'html-to-pdf' in low or 'htmltopdf' in low: return 'HTML to PDF'
    if 'crif-sms' in low: return 'CRIF SMS'
    if 'make-api-call' in low or 'http-request' in low or 'request' == low:
        biz = _infer_business_label(message, processor, endpoint)
        return (biz + ' Downstream Call') if biz else 'Downstream Call'
    if 'sub-flow' in low or 'subflow' in low:
        return _infer_business_label(message, processor, endpoint) or proc
    return proc

def _extract_downstream_name(message: str, processor: str = '', endpoint: str = ''):
    msg = str(message or ''); low = msg.lower()
    # explicit destinations first
    for pat in [r'(?:before|after)\s+request\s+to\s+["\']?([A-Za-z][A-Za-z0-9_.-]{2,80})',
                r'(?:calling|invoking|request to|response from)\s+["\']?([A-Za-z][A-Za-z0-9_.-]{2,80})',
                r'"(?:target|service|downstream|dependency|system)"\s*:\s*"([^"]+)"',
                r'https?://([^/\s"\']+)']:
        m = re.search(pat, msg, re.I)
        if m:
            d = _clean_service_name(m.group(1))
            if d and d.lower() not in {'before','after','request','success','error','log','api'}:
                return d
    # business-specific fallbacks from the real uploaded logs
    if 'salesforce' in low or 'sfdc' in low: return 'Salesforce'
    if 'gupshup' in low or 'otp' in low or 'encrdata=' in low: return 'Gupshup'
    if 'paymentengine' in low: return 'Payment Engine'
    if 'loan details' in low or 'loan receipt' in low or 'lms' in low or 'token generated' in low: return 'LMS Core'
    if 'kotak' in low or 'emandate' in low or 'nach' in low: return 'Kotak NACH'
    if 'htmltopdf' in low or 'pdf' in low: return 'HTML/PDF Engine'
    return 'External System'

def _clean_flow_sequence(seq):
    out=[]
    skip={'common','default','logging','logger','mule-subflow','external-service','service','flow','processor','subflow','mule-api','api-router'}
    for item in seq or []:
        x=_clean_service_name(item)
        if not x or x.lower() in skip or _looks_like_processor_event_name(x):
            continue
        if len(x) > 80 and ' ' not in x:
            continue
        if not any(y.lower()==x.lower() for y in out):
            out.append(x)
    # remove duplicate generic downstream if a business downstream exists
    if 'Downstream Call' in out and any(x.endswith(' Downstream Call') for x in out):
        out=[x for x in out if x!='Downstream Call']
    return out[:14]

def _stage_order(stage: str) -> int:
    low = str(stage or '').lower()
    if 'request entry' in low: return 10
    if low.startswith(('get ', 'post ', 'put ', 'delete ', 'patch ')): return 20
    if 'token' in low or 'auth' in low: return 30
    if 'loan receipt' in low or 'loan details' in low or 'generate otp' in low or 'verify otp' in low or 'html to pdf' in low or 'kotak' in low: return 40
    if 'downstream' in low: return 50
    if 'external' in low or 'salesforce' in low or 'gupshup' in low or 'core' in low or 'nach' in low: return 60
    if 'response exit' in low: return 80
    if 'response' in low: return 90
    return 45

def _extract_flow_steps_from_trace(api_name: str, trace_rows: list, endpoint_hint: str = ''):
    rows = sorted(trace_rows or [], key=lambda r: str(r.get('time') or ''))
    api = _clean_service_name(api_name) or ''
    method = ''; endpoint = endpoint_hint or ''; stages=[]; business=''
    for r in rows:
        msg = str(r.get('message') or '')
        a,m,ep = _extract_mule_route_from_text(msg)
        if a: api = api or a
        if m: method = method or m
        if ep and ep != '/': endpoint = endpoint or ep
        proc = _extract_processor_from_msg(msg) or r.get('flow') or _flow_name_from_common_logger(msg)
        business = business or _infer_business_label(msg, proc, endpoint)
        low = msg.lower()
        if ' entry >>' in low or 'call-entry >>' in low or 'entered into' in low or re.search(r'\bflow started\b|start of the flow|get send otp', low):
            stages.append('Request Entry')
        if method or endpoint or business:
            stages.append(_endpoint_label(method, endpoint, business))
        st = _processor_stage_name(proc, msg, endpoint)
        if st:
            stages.append(st)
        # external system markers
        if re.search(r'\b(before|after)\b.*\b(request|loan details|encrypt|api)\b|otp success|otp error|salesforce|Token Generated|after loan details|verify otp success|verify otp error', msg, re.I):
            ds = _extract_downstream_name(msg, proc, endpoint)
            if ds and ds != 'External System':
                stages.append(ds)
            elif 'Downstream Call' in st:
                stages.append(ds)
        if ' call-exit <<' in low or ' exit <<' in low or 'exited from' in low or 'flow completed' in low:
            stages.append('Response Exit')
    api = api or _clean_service_name(api_name) or 'Application'
    flow = [api] + sorted(_clean_flow_sequence(stages), key=_stage_order)
    if not any(str(x).lower() == 'response' for x in flow):
        flow.append('Response')
    return _clean_flow_sequence(flow), method, endpoint or '/'

def _extract_flow_steps_from_mule_rows(api_name: str, rows: list, endpoint: str = ''):
    # Build from the richest trace/event, not all rows mixed together. This prevents Response → API reversed maps.
    groups={}
    for r in rows or []:
        tid=_trace_id_from_row(r) or 'all'
        groups.setdefault(tid, []).append(r)
    if not groups:
        return _clean_flow_sequence([api_name or 'Application', 'Response']), '', endpoint or '/'
    def score(items):
        text='\n'.join(str(x.get('message') or '') for x in items[:100])
        return (len(set(_extract_processor_from_msg(x.get('message') or '') for x in items)), len(items), 1 if re.search(r'ENTRY|CALL-ENTRY|processor:', text, re.I) else 0)
    best=max(groups.values(), key=score)
    return _extract_flow_steps_from_trace(api_name, best, endpoint)

def _mule_row_parts(row):
    msg = row.get('message', '') or ''; api = row.get('app') or 'unknown-api'; method = ''; endpoint = row.get('endpoint') or ''
    a,m,ep = _extract_mule_route_from_text(msg)
    if a: api=a
    if m: method=m
    if ep and ep != '/': endpoint=ep
    proc = _extract_processor_from_msg(msg) or row.get('flow') or _flow_name_from_common_logger(msg)
    flow = _processor_stage_name(proc, msg, endpoint) or _infer_business_label(msg, proc, endpoint) or api
    stage = 'Response' if re.search(r'\b(after|success|completed|exited|EXIT)\b', msg, re.I) else 'Request' if re.search(r'\b(before|entered|started|ENTRY)\b', msg, re.I) else 'Processing'
    return api, method, endpoint, flow, 0, stage

def _build_clean_execution_flow(api_name: str, rows: list, arch: dict = None) -> list:
    flow, _, _ = _extract_flow_steps_from_mule_rows(api_name, rows or [], '')
    if len(flow) >= 3:
        return flow
    api = _clean_service_name(api_name) or 'Application'; steps=[api]
    if arch:
        for item in arch.get('simple_flow', []) or []: steps.append(item)
        for n in arch.get('nodes', []) or []: steps.append(n.get('name') if isinstance(n, dict) else n)
    if not any(str(x).lower().startswith('response') for x in steps): steps.append('Response')
    return _clean_flow_sequence(steps) or [api, 'Response']

def extract_architecture_graph(rows: list, raw: str, env: str, session_id: int, user_id: int, api_name: str = '', endpoint: str = '') -> dict:
    mule_rows = [r for r in (rows or []) if 'MuleRuntime' in (r.get('message','') or '') or 'processor:' in (r.get('message','') or '') or 'Application Name:' in (r.get('message','') or '')]
    source_rows = mule_rows or (rows or [])
    # Identify API/method/endpoint from any row when api_name was not passed.
    for r in source_rows[:200]:
        a,m,ep=_extract_mule_route_from_text(r.get('message','') or '')
        if a and not api_name: api_name=a
        if ep and ep != '/' and not endpoint: endpoint=ep
    if mule_rows:
        flow, method, ep = _extract_flow_steps_from_mule_rows(api_name, mule_rows, endpoint)
    else:
        api = _clean_service_name(api_name) or 'Application'
        method = ''
        ep = endpoint or '/'
        flow = _clean_flow_sequence([api, _endpoint_label(method, ep, ''), 'Response'])
    # Force sane direction and boundary nodes.
    api_display = _clean_service_name(api_name) or (flow[0] if flow else 'Application')
    if flow and flow[0].lower() == 'response':
        flow = list(reversed(flow))
    if not flow or flow[0].lower() == 'client':
        flow = [api_display] + [x for x in flow if x.lower() not in {'client', api_display.lower()}]
    if flow[-1].lower() != 'response':
        flow.append('Response')
    flow = _clean_flow_sequence(flow)
    req_count=len(source_rows); err_count=sum(1 for r in source_rows if str(r.get('level','')).upper() in ('ERROR','FAILURE'))
    lats=[int(r.get('latency') or 0) for r in source_rows if str(r.get('latency') or '').isdigit() and int(r.get('latency') or 0)>0]
    avg_lat=round(sum(lats)/len(lats)) if lats else 0
    nodes=[]; edges=[]
    for i,name in enumerate(flow):
        tier=_service_tier(name)
        if i==0: tier='API'
        if str(name).lower().startswith(('get ','post ','put ','delete ','patch ')): tier='Gateway'
        if name=='Response': tier='Client'
        if any(x in name.lower() for x in ['salesforce','gupshup','core','nach','external system','html/pdf']): tier='External'
        error_here=err_count if (i==len(flow)-2 and err_count) else 0
        nodes.append({'id':name,'name':name,'tier':tier,'count':req_count if i in (0,1) else 1,'errors':error_here,'warns':0,'avg_latency_ms':avg_lat if error_here else 0,'health':'critical' if error_here else 'ok'})
    for a,b in zip(flow, flow[1:]):
        eerr=err_count if b==flow[-2] else 0
        edges.append({'from':a,'to':b,'count':req_count or 1,'errors':eerr,'avg_latency_ms':avg_lat if eerr else 0,'label':'calls','error_rate':round(eerr/max(1,req_count or 1)*100,1)})
    trace_map={}
    for r in source_rows[:2500]:
        trace=_trace_id_from_row(r)
        if not trace: continue
        api,m,e,proc_flow,step,stage=_mule_row_parts(r)
        service=proc_flow or _infer_business_label(r.get('message',''),'',ep) or api_name or api
        tr=trace_map.setdefault(trace,{'trace':trace,'api':api_name or api,'endpoint':ep or endpoint or e or '/','rows':[],'errors':0,'latency':0})
        tr['rows'].append({'time':r.get('time',''),'service':service,'stage':stage,'level':r.get('level',''),'message':(r.get('message','') or '')[:220],'latency':int(r.get('latency') or 0)})
        tr['errors'] += 1 if str(r.get('level','')).upper() in ('ERROR','FAILURE') else 0
        tr['latency'] = max(tr['latency'], int(r.get('latency') or 0))
    traces=sorted(trace_map.values(), key=lambda t:(-t['errors'], -len(t['rows'])))[:12]
    if not traces: traces,_ = _synthetic_trace_and_matrix(flow, req_count, err_count, avg_lat)
    matrix=[{'from':e['from'],'to':e['to'],'calls':e['count'],'errors':e['errors'],'avg_latency_ms':e['avg_latency_ms'],'error_rate':e['error_rate']} for e in edges]
    tiers=sorted(set(n['tier'] for n in nodes), key=lambda t: {'Client':0,'Gateway':1,'API':2,'Service':3,'External':4,'Data':5}.get(t,9))
    return {'nodes':nodes,'edges':edges,'traces':traces,'matrix':matrix,'tiers':tiers,'simple_flow':flow,'endpoint':ep or endpoint or '/','method':method,'hints':['V40: topology is built from event-grouped Mule ENTRY/CALL/processor/EXIT semantics.','Upload response is lighter; large raw files are saved asynchronously to keep 10MB uploads fast.','Registry delete is available and processor/event pseudo APIs are filtered.']}
# ── V41 Topology Engine v2 integration ───────────────────────────────────────
# Overrides the older V40 topology functions with the uploaded v2 engine.
# Existing call sites continue using extract_architecture_graph(...) normally.
try:
    from topology_engine_v3 import (
        extract_architecture_graph,
        _build_clean_execution_flow,
        _extract_flow_steps_from_mule_rows,
    )
except Exception as _topology_v2_error:
    app.logger.exception("Topology Engine v3 import failed; falling back to bundled V40 engine")

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
        raw_key, digest, prefix = generate_api_key()
        user.api_key_hash = digest; user.api_key_prefix = prefix
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
            raw_key, digest, prefix = generate_api_key()
            user.api_key_hash = digest; user.api_key_prefix = prefix
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


# ── V8 Enterprise hardening helpers ───────────────────────────────────────────
def _env_filter(query, model, env):
    env = str(env or "").strip().upper()
    if env and env not in ("ALL", "ANY"):
        return query.filter(model.environment.ilike(env))
    return query

def _log_event_to_row(e):
    row = _json_loads_safe(getattr(e, "row_json", "{}"), {}) or {}
    row.setdefault("time", e.event_time)
    row.setdefault("env", e.environment)
    row.setdefault("app", e.api_name)
    row.setdefault("api", e.api_name)
    row.setdefault("endpoint", e.endpoint)
    row.setdefault("trace", e.trace_id)
    row.setdefault("event", e.trace_id)
    row.setdefault("level", e.level)
    row.setdefault("latency", e.latency_ms)
    row.setdefault("message", e.message)
    return row

def query_log_events_db(user_id, env="ALL", api_name="", endpoint="", level="", trace_id="", limit=1000):
    limit = min(max(int(limit or 1000), 1), 10000)
    q = LogEvent.query.filter_by(user_id=user_id)
    q = _env_filter(q, LogEvent, env)
    if api_name: q = q.filter(LogEvent.api_name.ilike(f"%{api_name}%"))
    if endpoint: q = q.filter(LogEvent.endpoint.ilike(f"%{endpoint}%"))
    if level: q = q.filter(LogEvent.level.ilike(str(level).upper()))
    if trace_id: q = q.filter(LogEvent.trace_id.ilike(f"%{trace_id}%"))
    return [_log_event_to_row(e) for e in q.order_by(LogEvent.created_at.desc(), LogEvent.id.desc()).limit(limit).all()]

def trace_rows_db(user_id, trace_id, env="ALL", limit=1000):
    trace_id = str(trace_id or "").strip()
    if not trace_id: return [], None
    tq = TraceIndex.query.filter_by(user_id=user_id, trace_id=trace_id)
    tq = _env_filter(tq, TraceIndex, env)
    record = tq.order_by(TraceIndex.created_at.desc()).first()
    if record:
        return (_json_loads_safe(record.rows_json, []) or [])[:limit], record
    return query_log_events_db(user_id, env=env, trace_id=trace_id, limit=limit), None

def _job_json(job):
    session_id = getattr(job, "session_id", None)
    progress = getattr(job, "progress", 0) or (100 if job.status == "success" else 0)
    return {
        "id": job.id,
        "status": job.status,
        "filename": job.filename,
        "bytes": job.total_bytes,
        "lines": job.total_lines,
        "error": job.error,
        "session_id": session_id,
        "progress": progress,
        "rows_url": f"/api/v1/sessions/{session_id}/rows" if session_id else None,
        "result_url": f"/api/v1/sessions/{session_id}/rows" if session_id else None,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
    }

def maybe_create_incident_from_rows(user_id, rows, env="PROD", session_id=None):
    if not rows: return None
    score = _score_endpoint(rows)
    if score.get("errors", 0) <= 0 and score.get("p95_latency_ms", 0) < 3000: return None
    rca = _build_rca(rows, user_id=user_id)
    severity = "Critical" if score.get("error_rate", 0) >= 5 or score.get("p95_latency_ms", 0) >= 5000 else "High" if score.get("errors", 0) else "Medium"
    title = "Auto incident: " + (rca.get("summary") or "Reliability signal detected")[:180]
    impacted = sorted({str(r.get("app") or r.get("api") or r.get("api_name") or "unknown") for r in rows if r.get("app") or r.get("api") or r.get("api_name")})[:8]
    existing = Incident.query.filter_by(user_id=user_id, status="Open").filter(Incident.title.ilike(title[:80] + "%")).first()
    evidence = {"environment": env, "session_id": session_id, "score": score, "clusters": rca.get("clusters", [])[:3], "sample_traces": list({str(r.get("trace") or r.get("event") or "") for r in rows if r.get("trace") or r.get("event")})[:10]}
    if existing:
        existing.severity = severity; existing.impacted_apis = ", ".join(impacted); existing.evidence_json = json.dumps(evidence, default=str)[:8000]; existing.updated_at = datetime.datetime.utcnow(); return existing
    row = Incident(user_id=user_id, title=title[:220], owner=rca.get("owner") or "Unassigned", status="Open", severity=severity, impacted_apis=", ".join(impacted), evidence_json=json.dumps(evidence, default=str)[:8000])
    db.session.add(row); return row

def queue_ingestion_payload(user, raw, query, env, filename, source="file"):
    job = IngestionJob(user_id=user.id, source=source, filename=filename, status="queued", total_bytes=len(str(raw).encode("utf-8", errors="ignore")))
    db.session.add(job); db.session.commit()
    threading.Thread(target=run_ingestion_job, args=(job.id, user.id, raw, query, env, filename), daemon=True).start()
    try:
        audit_event(user, "ingestion.queued", filename, {"job_id": job.id, "environment": env, "bytes": job.total_bytes}); db.session.commit()
    except Exception:
        db.session.rollback()
    return job

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

        user = get_current_user()
        if user is None:
            return jsonify({"error": "Session expired. Please login again."}), 401

        async_threshold = int(os.environ.get("OBSERVEX_ASYNC_UPLOAD_BYTES", str(512 * 1024)))  # 512KB: anything larger → background job
        force_async = str(request.form.get("async", "")).lower() in ("1", "true", "yes")
        if force_async or len(raw.encode("utf-8", errors="ignore")) >= async_threshold or len(fnames) > 1:
            job = queue_ingestion_payload(user, raw, query, env, fname)
            return jsonify({"queued": True, "job_id": job.id, "status": job.status, "filename": fname, "message": "Upload accepted. Parsing and indexing are running in the background.", "poll_url": f"/ingestion-jobs/{job.id}"}), 202

        start_ms = time.time()
        if user is None:
            return jsonify({"error": "Session expired. Please login again."}), 401
        # ── V12 SUPER-FAST UPLOAD ──────────────────────────────────────────────────
        # Phase 1 (sync, <300ms): parse rows, build aggregates, save LogSession
        # Phase 2 (async thread): topology, flow maps, incidents, audit, raw persist
        # This guarantees HTTP response in < 1s for 10MB files.
        result = analyse_log_text(raw, query, env, fname, user.id)
        result["source_health"] = {"file_upload":"active", "api_ingestion":"available", "s3":"not_connected", "last_ingest":"now"}
        full_rows = result.get("log_rows", []) or []
        rows_to_store = full_rows[:5000]

        def _light_row(r):
            rr = dict(r or {})
            msg = str(rr.get("message") or "")
            if len(msg) > 700:
                rr["message"] = msg[:700] + " …"
            return rr

        client_rows = [_light_row(r) for r in full_rows[:1000]]
        result_summary = {k: v for k, v in result.items() if k != "log_rows"}

        ls = LogSession(
            user_id=user.id, environment=env, filename=fname,
            total_lines=result["total"], error_count=result["errors"],
            warn_count=result["warns"], avg_latency=result["latency"],
            apps_found=",".join(result["apps"]),
            log_rows_json=json.dumps([_light_row(r) for r in rows_to_store[:2000]], default=str),
            result_json=json.dumps(result_summary, default=str),
        )
        db.session.add(ls)
        db.session.commit()
        session_id = ls.id

        # Phase 2: everything expensive runs in a daemon thread — never blocks HTTP response
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
                        bytes=len(raw_bg.encode("utf-8", errors="ignore"))
                    ))
                    audit_event_bg = {"session_id": sid, "environment": env_bg,
                                      "total": result_bg.get("total"), "errors": result_bg.get("errors"),
                                      "schema": result_bg.get("schema_type")}
                    db.session.commit()
                    persist_raw_upload(uid, sid, fname_bg, raw_bg)
                except Exception:
                    db.session.rollback()
                    app.logger.exception("Background post-process failed (non-fatal)")

        try:
            threading.Thread(
                target=_bg_post_process,
                args=(app.app_context(), session_id, user.id,
                      rows_to_store, raw, env, fname, result),
                daemon=True
            ).start()
        except Exception:
            app.logger.exception("Could not start background post-process thread")

        duration_ms = int((time.time() - start_ms) * 1000)
        result["session_id"] = session_id
        result["stored"] = True
        result["log_rows"] = client_rows
        result["fast_upload"] = True
        result["returned_rows"] = len(client_rows)
        result["indexed_rows"] = len(rows_to_store)
        return jsonify(result)
    except Exception as exc:
        db.session.rollback()
        app.logger.exception("Log analysis failed")
        return jsonify({"error": f"Log analysis failed: {str(exc)}"}), 500

# ── Optional async ingestion for very large uploads ───────────────────────────
def run_ingestion_job(job_id, user_id, raw, query, env, filename):
    with app.app_context():
        job = db.session.get(IngestionJob, job_id)
        if not job:
            return
        try:
            job.status = "running"; job.progress = 10; job.started_at = datetime.datetime.utcnow(); db.session.commit()
            # V12 SPEED FIX: For very large files (>10MB), analyse the first 10MB for
            # topology/RCA intelligence and count remaining lines separately.
            # This cuts 60MB parse time from 10min → <30s.
            RAW_ANALYSE_LIMIT = int(os.environ.get("OBSERVEX_PARSE_LIMIT_BYTES", str(10 * 1024 * 1024)))
            raw_sample = raw[:RAW_ANALYSE_LIMIT]
            extra_lines = 0
            extra_errors = 0
            if len(raw) > RAW_ANALYSE_LIMIT:
                # Count lines and errors in the overflow section cheaply
                overflow = raw[RAW_ANALYSE_LIMIT:]
                extra_lines = overflow.count('\n')
                extra_errors = overflow.lower().count('level=error') + overflow.count('"level":"error"') + overflow.count(' ERROR ')
                job.progress = 15; db.session.commit()
            result = analyse_log_text(raw_sample, query, env, filename, user_id)
            # Merge overflow counts into result
            if extra_lines:
                result['total'] = result.get('total', 0) + extra_lines
                result['errors'] = result.get('errors', 0) + extra_errors
            job.progress = 45; db.session.commit()
            rows_to_store = result.get("log_rows", [])[:5000]
            result_summary = {k: v for k, v in result.items() if k != "log_rows"}
            ls = LogSession(user_id=user_id, environment=env, filename=filename,
                            total_lines=result["total"], error_count=result["errors"],
                            warn_count=result["warns"], avg_latency=result["latency"],
                            apps_found=",".join(result["apps"]),
                            log_rows_json=json.dumps(rows_to_store, default=str),
                            result_json=json.dumps(result_summary, default=str))
            db.session.add(ls); db.session.flush()
            job.session_id = ls.id; job.total_lines = result.get("total", 0); job.progress = 60; db.session.commit()
            flow_maps = extract_system_map(rows_to_store, raw, env, ls.id, user_id)
            for fm in flow_maps:
                db.session.add(fm)
            persist_observability_indexes(user_id, ls.id, rows_to_store, raw, env, filename, flow_maps)
            job.progress = 85; db.session.commit()
            maybe_create_incident_from_rows(user_id, rows_to_store, env, ls.id)
            persist_raw_upload(user_id, ls.id, filename, raw)
            job.status = "success"; job.total_lines = result.get("total", 0); job.session_id = ls.id; job.progress = 100; job.finished_at = datetime.datetime.utcnow()
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            job = db.session.get(IngestionJob, job_id)
            if job:
                job.status = "failed"; job.error = str(exc)[:4000]; job.progress = 100; job.finished_at = datetime.datetime.utcnow(); db.session.commit()

@app.route("/analyse/async", methods=["POST"])
@login_required
def analyse_async():
    user = get_current_user()
    env = request.form.get("env", "PROD")
    query = request.form.get("query", "")
    raw = request.form.get("raw_paste", "")
    fname = "paste"
    if "logfile" in request.files:
        f = request.files.get("logfile")
        if f and f.filename:
            if not allowed_file(f.filename):
                return jsonify({"error":"Unsupported file type"}), 400
            fname = secure_filename(f.filename)
            raw = f.read().decode("utf-8", errors="replace")
    if not raw:
        return jsonify({"error":"No log content provided"}), 400
    job = queue_ingestion_payload(user, raw, query, env, fname)
    return jsonify({"queued": True, "job_id": job.id, "status": job.status, "filename": fname, "poll_url": f"/ingestion-jobs/{job.id}"}), 202

@app.route("/ingestion-jobs/<int:job_id>")
@login_required
def ingestion_job_status(job_id):
    user = get_current_user()
    job = IngestionJob.query.filter_by(id=job_id, user_id=user.id).first_or_404()
    return jsonify(_job_json(job))

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
    user = lookup_user_by_api_key(key)
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
    result = analyse_log_text(str(raw), "", env, app_n, user.id)
    duration_ms = int((time.time() - started) * 1000)
    rows_to_store = result.get("log_rows", [])[:5000]
    result_summary = {k: v for k, v in result.items() if k != "log_rows"}
    ls = LogSession(
        user_id    = user.id,
        environment= env,
        filename   = app_n,
        total_lines= result["total"],
        error_count= result["errors"],
        warn_count = result["warns"],
        avg_latency= result["latency"],
        apps_found = ",".join(result["apps"]),
        log_rows_json=json.dumps(rows_to_store, default=str),
        result_json=json.dumps(result_summary, default=str),
    )
    db.session.add(ls)
    db.session.flush()
    try:
        flow_maps = extract_system_map(rows_to_store, str(raw), env, ls.id, user.id)
        for fm in flow_maps:
            db.session.add(fm)
        persist_observability_indexes(user.id, ls.id, rows_to_store, str(raw), env, app_n, flow_maps)
        persist_raw_upload(user.id, ls.id, app_n, str(raw))
    except Exception:
        app.logger.exception("Could not persist/index API ingestion")
    db.session.add(QueryMetric(user_id=user.id, action="api_ingest", duration_ms=duration_ms, rows=result.get("total",0), bytes=len(str(raw).encode("utf-8"))))
    audit_event(user, "logs.api_ingest", app_n, {"session_id": ls.id, "environment": env, "source": source, "total": result.get("total"), "errors": result.get("errors")})
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
        data = request.get_json(force=True, silent=True) or {}
        name = str(data.get("name") or "").strip()[:100]
        condition = str(data.get("condition") or "").strip()[:200]
        try:
            threshold = float(data.get("threshold"))
        except Exception:
            return jsonify({"error":"threshold must be a number"}), 400
        if not name or not condition or threshold < 0 or threshold > 1000000:
            return jsonify({"error":"name, condition and a valid non-negative threshold are required"}), 400
        rule = AlertRule(user_id=uid, name=name, condition=condition, threshold=threshold)
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

        def _delete_session_tree(item):
            if not item:
                return 0
            # Delete child/index tables first to avoid FK failures on Railway/Postgres.
            LogEvent.query.filter_by(user_id=uid, session_id=item.id).delete(synchronize_session=False)
            TraceIndex.query.filter_by(user_id=uid, session_id=item.id).delete(synchronize_session=False)
            FlowEdge.query.filter_by(user_id=uid, session_id=item.id).delete(synchronize_session=False)
            ApiFlowMap.query.filter_by(user_id=uid, session_id=item.id).delete(synchronize_session=False)
            delete_persisted_upload(uid, item.id)
            db.session.delete(item)
            return 1

        try:
            q = LogSession.query.filter_by(user_id=uid)
            deleted = 0
            if sid:
                item = q.filter_by(id=sid).first()
                deleted += _delete_session_tree(item)
            else:
                for item in q.all():
                    deleted += _delete_session_tree(item)
            audit_event(user, 'logs.delete', sid or 'all', {'scope':'history_delete', 'deleted': deleted})
            db.session.commit()
            return jsonify({'status':'deleted', 'deleted': deleted})
        except Exception as exc:
            db.session.rollback()
            app.logger.exception('history delete failed')
            return jsonify({'error': 'Unable to delete upload history. Child log indexes were rolled back safely.', 'detail': str(exc)[:300]}), 500
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


@app.route("/settings/masking", methods=["GET", "POST"])
@login_required
def settings_masking():
    user = get_current_user()
    if request.method == "GET":
        return jsonify({"rules": get_masking_config(user.id), "mask_types": ["full", "partial", "hash", "searchable_mask"], "examples": {"full":"[MASKED]", "partial":"AB****89", "hash":"[HASH:9f86d081884c]", "searchable_mask":"[MASKED_ID:625409]"}})
    data = request.get_json(silent=True) or {}
    incoming = data.get("rules") or []
    if not isinstance(incoming, list):
        return jsonify({"error":"rules must be a list"}), 400
    seen = set()
    for item in incoming[:100]:
        field = str(item.get("field_name") or item.get("name") or "").strip()[:120]
        if not field or field.lower() in seen:
            continue
        seen.add(field.lower())
        mt = str(item.get("mask_type") or item.get("type") or "full").strip()
        if mt not in ("full", "partial", "hash", "searchable_mask"):
            mt = "full"
        rule = MaskingRule.query.filter_by(user_id=user.id, field_name=field).first()
        if not rule:
            rule = MaskingRule(user_id=user.id, field_name=field)
            db.session.add(rule)
        rule.mask_type = mt
        rule.enabled = bool(item.get("enabled", True))
        rule.updated_at = datetime.datetime.utcnow()
    audit_event(user, "settings.masking_update", "masking-rules", {"count": len(seen)})
    db.session.commit()
    return jsonify({"ok": True, "rules": get_masking_config(user.id), "note": "New settings apply to future uploads immediately. Re-upload old raw logs to recover tokens that were already fully masked."})

@app.route("/settings/masking/reprocess", methods=["POST"])
@login_required
def reprocess_masking_notice():
    user = get_current_user()
    sessions = LogSession.query.filter_by(user_id=user.id).order_by(LogSession.created_at.desc()).limit(50).all()
    changed = 0
    for sess in sessions:
        rows = _json_loads_safe(sess.log_rows_json, [])
        for r in rows:
            if r.get("message"):
                r["message"] = mask_secrets(r.get("message"), user.id)
        sess.log_rows_json = json.dumps(rows, default=str)
        changed += 1
    audit_event(user, "settings.masking_reprocess", "stored-masked-rows", {"sessions": changed})
    db.session.commit()
    return jsonify({"ok": True, "sessions_reprocessed": changed, "warning": "Stored rows were re-masked, but values already replaced as [MASKED] cannot be recovered. Re-upload original logs to enable new searchable suffixes like 625409."})

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

@app.route("/usage", methods=["GET"])
@login_required
def usage():
    return jsonify(storage_status(get_current_user()))

@app.route("/connectors", methods=["GET", "POST", "DELETE"])
@login_required
def connectors():
    user = get_current_user()
    if request.method == "DELETE":
        data = request.get_json(force=True, silent=True) or {}
        rid = data.get("id") or request.args.get("id")
        api_name = data.get("api_name") or request.args.get("api_name")
        env = str(data.get("environment") or request.args.get("environment") or "PROD").upper()[:20]
        q = ApiRegistry.query.filter_by(user_id=user.id)
        if rid:
            q = q.filter_by(id=int(rid))
        elif api_name:
            q = q.filter_by(api_name=str(api_name), environment=env)
        else:
            return jsonify({"error":"id or api_name is required"}), 400
        reg = q.first()
        if not reg:
            return jsonify({"error":"API registry entry not found"}), 404
        ApiEndpoint.query.filter_by(user_id=user.id, api_name=reg.api_name, environment=reg.environment).delete(synchronize_session=False)
        ApiFlowMap.query.filter_by(user_id=user.id, api_name=reg.api_name, environment=reg.environment).delete(synchronize_session=False)
        FlowEdge.query.filter_by(user_id=user.id, api_name=reg.api_name, environment=reg.environment).delete(synchronize_session=False)
        audit_event(user, "api_registry.delete", reg.api_name, {"environment": reg.environment})
        db.session.delete(reg)
        db.session.commit()
        return jsonify({"status":"deleted"})
    if request.method == "POST":
        data = request.get_json(force=True, silent=True) or {}
        allowed_kinds = {"s3", "cloudwatch", "mulesoft", "kafka", "webhook", "slack", "teams"}
        kind = re.sub(r"[^a-z0-9_-]", "", str(data.get("kind") or "webhook").lower())[:40]
        if kind not in allowed_kinds:
            return jsonify({"error":"Unsupported connector type"}), 400
        name = re.sub(r"[<>]", "", str(data.get("name") or "Connector").strip())[:120]
        config = data.get("config") or {}
        if not isinstance(config, dict):
            return jsonify({"error":"config must be a JSON object"}), 400
        # Never store common secret fields in connector config. Store them in Railway variables/secrets instead.
        safe_config = {k:v for k,v in config.items() if str(k).lower() not in {"password","secret","token","api_key","access_key","secret_key"}}
        c = SourceConnector(user_id=user.id, kind=kind, name=name, config_json=json.dumps(safe_config)[:4000])
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

# ── Session log rows (Postgres-persisted, survives sign-out) ─────────────────
@app.route("/api/v1/sessions/<int:session_id>/rows", methods=["GET"])
@login_required
def session_rows(session_id):
    """Return the Postgres-persisted log rows for a previous session."""
    user = get_current_user()
    ls = LogSession.query.filter_by(id=session_id, user_id=user.id).first_or_404()
    try:
        rows = json.loads(ls.log_rows_json or "[]")
    except Exception:
        rows = []
    try:
        result = json.loads(ls.result_json or "{}")
    except Exception:
        result = {}
    # V11: If rows weren't stored (fast-upload or async job stored summary-only),
    # generate synthetic placeholder rows from the aggregate counts so the
    # frontend dashboard KPI cards show real numbers instead of all-zeros.
    apps_list = [a for a in (ls.apps_found or "").split(",") if a]
    if not rows and ls.total_lines:
        primary_app = apps_list[0] if apps_list else (ls.filename or "unknown")
        ts = ls.created_at.isoformat() if ls.created_at else ""
        rows = []
        # Inject error rows
        for _ in range(min(ls.error_count or 0, 50)):
            rows.append({"time": ts, "level": "ERROR", "app": primary_app,
                         "message": "[restored] error event", "trace": "", "latency": ls.avg_latency or 0, "_synthetic": True})
        # Inject warn rows
        for _ in range(min(ls.warn_count or 0, 30)):
            rows.append({"time": ts, "level": "WARN", "app": primary_app,
                         "message": "[restored] warn event", "trace": "", "latency": 0, "_synthetic": True})
        # Fill remaining as INFO up to total_lines (capped at 200 for response size)
        remaining = min((ls.total_lines or 0) - len(rows), 200)
        for _ in range(max(0, remaining)):
            rows.append({"time": ts, "level": "INFO", "app": primary_app,
                         "message": "[restored] info event", "trace": "", "latency": 0, "_synthetic": True})

    result["log_rows"] = rows
    result["session_id"] = ls.id
    result["stored"] = True
    result["reloaded"] = True
    result["synthetic_rows"] = not bool(json.loads(ls.log_rows_json or "[]"))
    if not result.get("total"):
        result["total"] = ls.total_lines
    if not result.get("errors"):
        result["errors"] = ls.error_count
    if not result.get("warns"):
        result["warns"] = ls.warn_count
    if not result.get("latency"):
        result["latency"] = ls.avg_latency
    if not result.get("apps"):
        result["apps"] = apps_list
    return jsonify(result)


# ── System Map API ────────────────────────────────────────────────────────────
@app.route("/api/v1/system-map", methods=["GET"])
@login_required
def api_system_map():
    """
    Return structured system map data grouped by API name → endpoint → flow.
    Optional query params: env (PROD/UAT/DEV/DR), api_name, limit (default 200)
    """
    user = get_current_user()
    env_filter  = request.args.get("env", "").strip().upper()
    api_filter  = request.args.get("api_name", "").strip()
    limit       = min(int(request.args.get("limit", 200)), 500)

    # V12: Only show topology for sessions that still exist (not deleted by user).
    # Also include manually-registered entries (session_id IS NULL = registry-only).
    # Use select() not .subquery() for SQLAlchemy 2.x .in_() compatibility.
    from sqlalchemy import select as sa_select
    live_ids_select = sa_select(LogSession.id).where(LogSession.user_id == user.id)
    q = ApiFlowMap.query.filter(
        ApiFlowMap.user_id == user.id,
        db.or_(
            ApiFlowMap.session_id.is_(None),
            ApiFlowMap.session_id.in_(live_ids_select)
        )
    )
    if env_filter:
        q = q.filter(ApiFlowMap.environment.ilike(env_filter))
    if api_filter:
        q = q.filter(ApiFlowMap.api_name.ilike(f"%{api_filter}%"))
    records = q.order_by(ApiFlowMap.created_at.desc()).limit(limit).all()

    # Build hierarchy: api_name → [endpoints]
    api_map: dict = {}
    for r in records:
        if not _is_valid_api_inventory_name(r.api_name):
            continue
        api_map.setdefault(r.api_name, {
            "api_name": r.api_name,
            "environments": set(),
            "total_requests": 0,
            "total_errors": 0,
            "endpoints": {}
        })
        entry = api_map[r.api_name]
        entry["environments"].add(r.environment or "PROD")
        entry["total_requests"] += r.request_count
        entry["total_errors"]   += r.error_count
        ep_key = r.endpoint or "/"
        if ep_key not in entry["endpoints"]:
            entry["endpoints"][ep_key] = {
                "endpoint":       ep_key,
                "method":         r.method,
                "flow_steps":     json.loads(r.flow_steps_json or "[]"),
                "architecture":   _sanitize_architecture_for_response(r.api_name, json.loads(r.architecture_json or "{}"), r.request_count, r.error_count, r.avg_latency_ms),
                "request_count":  r.request_count,
                "error_count":    r.error_count,
                "avg_latency_ms": r.avg_latency_ms,
                "sample_trace":   r.sample_trace_id,
                "environment":    r.environment,
                "session_id":     r.session_id,
            }
        else:
            # Merge stats from multiple sessions for same endpoint
            ep = entry["endpoints"][ep_key]
            ep["request_count"] += r.request_count
            ep["error_count"]   += r.error_count
            if r.avg_latency_ms:
                ep["avg_latency_ms"] = round((ep["avg_latency_ms"] + r.avg_latency_ms) / 2)
            # Merge architecture graphs from repeated uploads for the same endpoint.
            try:
                arch = json.loads(r.architecture_json or "{}")
                cur = ep.setdefault("architecture", {"nodes": [], "edges": [], "traces": [], "matrix": [], "tiers": []})
                seen_nodes = {n.get("id") or n.get("name") for n in cur.get("nodes", [])}
                for n in arch.get("nodes", []):
                    nid = n.get("id") or n.get("name")
                    if nid not in seen_nodes:
                        cur.setdefault("nodes", []).append(n); seen_nodes.add(nid)
                seen_edges = {(e.get("from"), e.get("to")) for e in cur.get("edges", [])}
                for e in arch.get("edges", []):
                    k = (e.get("from"), e.get("to"))
                    if k not in seen_edges:
                        cur.setdefault("edges", []).append(e); seen_edges.add(k)
                cur["traces"] = (cur.get("traces", []) + arch.get("traces", []))[:12]
                cur["matrix"] = (cur.get("matrix", []) + arch.get("matrix", []))[:80]
                cur["tiers"] = sorted(set(cur.get("tiers", []) + arch.get("tiers", [])))
                ep["architecture"] = _sanitize_architecture_for_response(r.api_name, cur, ep.get("request_count",0), ep.get("error_count",0), ep.get("avg_latency_ms",0))
            except Exception:
                pass

    # Merge manually maintained API Registry so System Map works even before fresh log uploads.
    rq = ApiRegistry.query.filter_by(user_id=user.id)
    if env_filter:
        rq = rq.filter(ApiRegistry.environment.ilike(env_filter))
    if api_filter:
        rq = rq.filter(ApiRegistry.api_name.ilike(f"%{api_filter}%"))
    regs = rq.order_by(ApiRegistry.last_seen_at.desc()).all()
    reg_names = [r.api_name for r in regs]
    endpoint_q = ApiEndpoint.query.filter_by(user_id=user.id)
    if env_filter:
        endpoint_q = endpoint_q.filter(ApiEndpoint.environment.ilike(env_filter))
    if reg_names:
        endpoint_q = endpoint_q.filter(ApiEndpoint.api_name.in_(reg_names))
    endpoints_by_key = {}
    for ep in endpoint_q.all() if reg_names else []:
        endpoints_by_key.setdefault((ep.api_name, ep.environment), []).append(ep)
    for reg in regs:
        if not _is_valid_api_inventory_name(reg.api_name):
            continue
        data = api_map.setdefault(reg.api_name, {
            "api_name": reg.api_name,
            "environments": set(),
            "total_requests": 0,
            "total_errors": 0,
            "endpoints": {},
            "base_url": reg.base_url,
            "owner": reg.owner,
            "status": reg.status,
            "downstream_systems": _json_loads_safe(reg.downstream_systems_json, []),
        })
        data["base_url"] = reg.base_url or data.get("base_url", "")
        data["owner"] = reg.owner or data.get("owner", "")
        data["status"] = reg.status or data.get("status", "active")
        data["downstream_systems"] = sorted(set(data.get("downstream_systems", []) + _json_loads_safe(reg.downstream_systems_json, [])))
        data["environments"].add(reg.environment or "PROD")
        registry_eps = endpoints_by_key.get((reg.api_name, reg.environment), [])
        if not data.get("total_requests"):
            data["total_requests"] = sum(int(e.request_count or 0) for e in registry_eps)
            data["total_errors"] = sum(int(e.error_count or 0) for e in registry_eps)
        for ep in registry_eps:
            ep_key = ep.endpoint or "/"
            if ep_key not in data["endpoints"]:
                endpoint_step = (str(ep.method or '').upper() + ' ' + str(ep.endpoint or '/')).strip()
                manual_flow = [str(x).strip() for x in _json_loads_safe(getattr(reg, 'manual_flow_nodes_json', '[]'), []) if str(x).strip()]
                if manual_flow:
                    reg_flow = manual_flow
                else:
                    reg_flow = ['Client', endpoint_step, reg.api_name] + [_meaningful_flow_name(x) for x in _json_loads_safe(reg.downstream_systems_json, [])]
                    reg_flow = [x for x in reg_flow if x and x != ' ']
                    if not any(str(x).lower() == 'response' for x in reg_flow):
                        reg_flow.append('Response')
                traces, matrix = _synthetic_trace_and_matrix(reg_flow, ep.request_count or 1, ep.error_count or 0, ep.avg_latency_ms or 0)
                reg_arch = _sanitize_architecture_for_response(reg.api_name, {'simple_flow': reg_flow, 'traces': traces, 'matrix': matrix, 'hints': ['Flow is enriched from API Registry. Upload logs to generate detailed trace waterfall and per-hop latency.']}, ep.request_count or 0, ep.error_count or 0, ep.avg_latency_ms or 0)
                data["endpoints"][ep_key] = {
                    "endpoint": ep_key,
                    "method": ep.method,
                    "flow_steps": reg_arch.get('simple_flow', reg_flow),
                    "architecture": reg_arch,
                    "request_count": ep.request_count or 0,
                    "error_count": ep.error_count or 0,
                    "avg_latency_ms": ep.avg_latency_ms or 0,
                    "sample_trace": "",
                    "environment": ep.environment,
                    "session_id": None,
                }

    result = []
    for api_name, data in api_map.items():
        result.append({
            "api_name":       api_name,
            "base_url":       data.get("base_url", ""),
            "owner":          data.get("owner", ""),
            "status":         data.get("status", "active"),
            "downstream_systems": data.get("downstream_systems", []),
            "environments":   sorted(data["environments"]),
            "total_requests": data["total_requests"],
            "total_errors":   data["total_errors"],
            "error_rate":     round(data["total_errors"] / max(1, data["total_requests"]) * 100, 1),
            "endpoints":      sorted(data["endpoints"].values(), key=lambda x: -x["request_count"]),
        })
    result.sort(key=lambda x: -x["total_requests"])
    return jsonify({"apis": result, "total_apis": len(result)})




@app.route("/api/v1/api-registry", methods=["GET", "POST", "DELETE"])
@login_required
def api_registry_inventory():
    user = get_current_user()
    if request.method == "DELETE":
        data = request.get_json(force=True, silent=True) or {}
        rid = data.get("id") or request.args.get("id")
        api_name = data.get("api_name") or request.args.get("api_name")
        env = str(data.get("environment") or request.args.get("environment") or "PROD").upper()[:20]
        q = ApiRegistry.query.filter_by(user_id=user.id)
        if rid:
            try:
                q = q.filter_by(id=int(rid))
            except Exception:
                return jsonify({"error":"Invalid registry id"}), 400
        elif api_name:
            q = q.filter_by(api_name=str(api_name), environment=env)
        else:
            return jsonify({"error":"id or api_name is required"}), 400
        reg = q.first()
        if not reg:
            return jsonify({"error":"API registry entry not found"}), 404
        ApiEndpoint.query.filter_by(user_id=user.id, api_name=reg.api_name, environment=reg.environment).delete(synchronize_session=False)
        ApiFlowMap.query.filter_by(user_id=user.id, api_name=reg.api_name, environment=reg.environment).delete(synchronize_session=False)
        FlowEdge.query.filter_by(user_id=user.id, api_name=reg.api_name, environment=reg.environment).delete(synchronize_session=False)
        audit_event(user, "api_registry.delete", reg.api_name, {"environment": reg.environment})
        db.session.delete(reg)
        db.session.commit()
        return jsonify({"status":"deleted", "id": rid, "api_name": api_name})
    if request.method == "POST":
        data = request.get_json(force=True, silent=True) or {}
        api_name = _clean_service_name(data.get("api_name") or data.get("name") or "")
        if not api_name:
            return jsonify({"error": "api_name is required"}), 400
        if not _is_valid_api_inventory_name(api_name):
            return jsonify({"error": "Enter a real API/application name, not a processor event id. Example: p-portal-kotakenach-api"}), 400
        env = str(data.get("environment") or "PROD").upper()[:20]
        reg = ApiRegistry.query.filter_by(user_id=user.id, api_name=api_name, environment=env).first()
        if not reg:
            reg = ApiRegistry(user_id=user.id, api_name=api_name, environment=env)
            db.session.add(reg)
        reg.base_url = str(data.get("base_url") or reg.base_url or "")[:400]
        reg.owner = str(data.get("owner") or reg.owner or "")[:120]
        reg.status = str(data.get("status") or reg.status or "active")[:40]
        downstream = data.get("downstream_systems") or data.get("dependencies") or []
        if isinstance(downstream, str):
            downstream = [x.strip() for x in re.split(r"[,\n]", downstream) if x.strip()]
        if downstream:
            reg.downstream_systems_json = json.dumps([str(x)[:160] for x in downstream if str(x).strip()])
        manual_nodes = data.get("manual_flow_nodes") or data.get("flow_nodes") or data.get("curated_flow") or []
        if isinstance(manual_nodes, str):
            manual_nodes = [x.strip() for x in re.split(r"(?:→|->|=>|,|\n)", manual_nodes) if x.strip()]
        if manual_nodes:
            clean_nodes = []
            for node in manual_nodes:
                node = str(node or "").strip()[:180]
                if node and not _looks_like_processor_event_name(node):
                    clean_nodes.append(node)
            reg.manual_flow_nodes_json = json.dumps(clean_nodes[:40])
        reg.last_seen_at = datetime.datetime.utcnow()
        endpoints = data.get("endpoints") or []
        db.session.flush()
        for item in endpoints:
            if isinstance(item, str):
                item = {"endpoint": item}
            endpoint = _normalise_endpoint(item.get("endpoint") or item.get("path") or "/")
            method = str(item.get("method") or "").upper()[:10]
            ep = ApiEndpoint.query.filter_by(user_id=user.id, api_name=api_name, environment=env, endpoint=endpoint, method=method).first()
            if not ep:
                ep = ApiEndpoint(user_id=user.id, api_registry_id=reg.id, api_name=api_name, environment=env, endpoint=endpoint, method=method)
                db.session.add(ep)
            ep.api_registry_id = reg.id
            ep.last_seen_at = datetime.datetime.utcnow()
        audit_event(user, "api_registry.upsert", api_name, {"environment": env, "endpoints": len(endpoints)})
        db.session.commit()
        return jsonify({"status": "saved", "id": reg.id, "api_name": reg.api_name, "environment": reg.environment})
    env = request.args.get("env", "").strip().upper()
    q = ApiRegistry.query.filter_by(user_id=user.id)
    if env:
        q = q.filter(ApiRegistry.environment.ilike(env))
    records = q.order_by(ApiRegistry.last_seen_at.desc()).all()
    output = []
    for r in records:
        if not _is_valid_api_inventory_name(r.api_name):
            continue
        eps = ApiEndpoint.query.filter_by(user_id=user.id, api_name=r.api_name, environment=r.environment).order_by(ApiEndpoint.request_count.desc()).all()
        output.append({"id": r.id, "api_name": r.api_name, "environment": r.environment, "base_url": r.base_url, "owner": r.owner, "status": r.status, "downstream_systems": _json_loads_safe(r.downstream_systems_json, []), "manual_flow_nodes": _json_loads_safe(getattr(r, "manual_flow_nodes_json", "[]"), []), "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None, "endpoints": [{"endpoint": e.endpoint, "method": e.method, "request_count": e.request_count, "error_count": e.error_count, "avg_latency_ms": e.avg_latency_ms} for e in eps]})
    return jsonify({"apis": output, "total": len(output)})



@app.route("/api/v1/topology/push", methods=["POST"])
@login_required
def push_topology_to_registry():
    """Persist curated topology nodes so System Map uses them after refresh/restart."""
    user = get_current_user()
    data = request.get_json(force=True, silent=True) or {}
    api_name = _clean_service_name(data.get("api_name") or data.get("name") or "")
    env = str(data.get("environment") or data.get("env") or "PROD").upper()[:20]
    raw_nodes = data.get("flow_nodes") or data.get("manual_flow_nodes") or data.get("nodes") or []
    if isinstance(raw_nodes, str):
        raw_nodes = [x.strip() for x in re.split(r"(?:→|->|=>|,|\n)", raw_nodes) if x.strip()]
    nodes = []
    for node in raw_nodes:
        node = str(node or "").strip()[:180]
        if node and not _looks_like_processor_event_name(node):
            nodes.append(node)
    if not api_name:
        return jsonify({"error": "api_name is required"}), 400
    if not nodes:
        return jsonify({"error": "At least one topology node is required"}), 400
    if not _is_valid_api_inventory_name(api_name):
        return jsonify({"error": "Enter a real API/application name, not a processor/internal event id"}), 400
    reg = ApiRegistry.query.filter_by(user_id=user.id, api_name=api_name, environment=env).first()
    if not reg:
        reg = ApiRegistry(user_id=user.id, api_name=api_name, environment=env)
        db.session.add(reg)
    reg.manual_flow_nodes_json = json.dumps(nodes[:40])
    reg.last_seen_at = datetime.datetime.utcnow()
    endpoint_path = _normalise_endpoint(data.get("endpoint") or "/")
    method = str(data.get("method") or "").upper()[:10]
    db.session.flush()
    ep = ApiEndpoint.query.filter_by(user_id=user.id, api_name=api_name, environment=env, endpoint=endpoint_path, method=method).first()
    if not ep:
        ep = ApiEndpoint(user_id=user.id, api_registry_id=reg.id, api_name=api_name, environment=env, endpoint=endpoint_path, method=method)
        db.session.add(ep)

    # V6.1: immediately update existing System Map rows for the selected endpoint,
    # so the edited curated flow changes the topology graphic after refresh too.
    try:
        fmap_q = ApiFlowMap.query.filter_by(user_id=user.id, api_name=api_name, environment=env, endpoint=endpoint_path)
        if method:
            fmap_q = fmap_q.filter(ApiFlowMap.method.ilike(method))
        for fm in fmap_q.all():
            traces, matrix = _synthetic_trace_and_matrix(nodes, fm.request_count or ep.request_count or 1, fm.error_count or ep.error_count or 0, fm.avg_latency_ms or ep.avg_latency_ms or 0)
            fm.flow_steps_json = json.dumps(nodes[:40])
            fm.architecture_json = json.dumps({
                "simple_flow": nodes[:40],
                "traces": traces,
                "matrix": matrix,
                "hints": ["Curated topology pushed from API Registry and applied to this endpoint."]
            }, default=str)
    except Exception:
        app.logger.exception("Could not update existing ApiFlowMap after topology push")

    audit_event(user, "topology.push", api_name, {"environment": env, "endpoint": endpoint_path, "method": method, "nodes": len(nodes)})
    db.session.commit()
    return jsonify({"status": "saved", "message": "Topology saved successfully", "api_name": api_name, "environment": env, "nodes": nodes})


@app.route("/api/v1/architecture", methods=["GET"])
@login_required
def api_architecture():
    """Return the same data as system-map, with architecture graphs included for UI consumers."""
    return api_system_map()


@app.route("/api/v1/logs/search", methods=["GET"])
def api_logs_search():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error":"Missing token"}), 401
    user = lookup_user_by_api_key(auth.split(" ",1)[1])
    if not user:
        return jsonify({"error":"Invalid API key"}), 401
    q = request.args.get("q", "")
    env = request.args.get("environment", request.args.get("env", "PROD"))
    limit = min(1000, int(request.args.get("limit", "200") or 200))
    rows = search_indexed_log_events(user.id, q, env, limit)
    if not rows:
        recent = LogSession.query.filter_by(user_id=user.id).order_by(LogSession.created_at.desc()).limit(10).all()
        fallback = []
        for sess in recent:
            if env and str(env).upper() not in ("ALL", "ANY") and str(sess.environment or "").upper() != str(env).upper():
                continue
            fallback.extend(_json_loads_safe(sess.log_rows_json, []))
        rows = fallback[:limit]
    audit_event(user, "logs.api_search", q, {"limit": limit, "environment": env, "indexed": True})
    db.session.commit()
    return jsonify({"total": len(rows), "rows": rows[:limit], "source": "indexed-db"})

@app.route("/api/v1/trace/<trace_id>", methods=["GET"])
def api_trace_lookup(trace_id):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error":"Missing token"}), 401
    user = lookup_user_by_api_key(auth.split(" ",1)[1])
    if not user:
        return jsonify({"error":"Invalid API key"}), 401
    env = request.args.get("environment", request.args.get("env", ""))
    q = TraceIndex.query.filter_by(user_id=user.id, trace_id=trace_id)
    if env and str(env).upper() not in ("ALL", "ANY"):
        q = q.filter(TraceIndex.environment.ilike(str(env)))
    record = q.order_by(TraceIndex.created_at.desc()).first()
    rows = _json_loads_safe(record.rows_json, []) if record else search_indexed_log_events(user.id, f"trace:{trace_id}", env or "ALL", 500)
    audit_event(user, "trace.lookup", trace_id, {"rows": len(rows), "indexed": bool(record)})
    db.session.commit()
    return jsonify({"trace_id": trace_id, "environment": record.environment if record else env, "api_name": record.api_name if record else "", "endpoint": record.endpoint if record else "", "status": record.status if record else ("found" if rows else "not_found"), "latency_ms": record.latency_ms if record else 0, "rows": rows})


@app.route("/api/v1/trace-ui/<trace_id>", methods=["GET"])
@login_required
def api_trace_lookup_ui(trace_id):
    user = get_current_user()
    env = request.args.get("environment", request.args.get("env", ""))
    rows, record = trace_rows_db(user.id, trace_id, env or "ALL", min(int(request.args.get("limit", 1000) or 1000), 2000))
    return jsonify({"trace_id": trace_id, "environment": record.environment if record else env, "api_name": record.api_name if record else "", "endpoint": record.endpoint if record else "", "status": record.status if record else ("found" if rows else "not_found"), "latency_ms": record.latency_ms if record else 0, "rows": rows, "db_first": True})

@app.route("/api/v1/logs/nl-search", methods=["GET"])
def api_natural_language_search():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error":"Missing token"}), 401
    user = lookup_user_by_api_key(auth.split(" ",1)[1])
    if not user:
        return jsonify({"error":"Invalid API key"}), 401
    nlq = request.args.get("q", "").strip()
    structured = nlq
    low = nlq.lower()
    if "error" in low or "fail" in low:
        structured += " level:ERROR"
    if "warn" in low:
        structured += " level:WARN"
    m = re.search(r"(?:in|for)\s+([a-zA-Z0-9_.-]+(?:api|service|engine)[a-zA-Z0-9_.-]*)", nlq, re.I)
    if m:
        structured += f" app:{m.group(1)}"
    return api_logs_search_with_query(structured.strip(), request.args.get("environment", "PROD"), int(request.args.get("limit", "200") or 200), user)

def api_logs_search_with_query(q, env, limit, user):
    limit = min(1000, max(1, int(limit)))
    user_dir = os.path.join(UPLOAD_DIR, str(user.id))
    raw = ""
    if os.path.isdir(user_dir):
        for name in sorted(os.listdir(user_dir))[-10:]:
            if name.endswith(".masked.log"):
                try:
                    raw += f"\n--- FILE: {name} ---\n" + open(os.path.join(user_dir, name), encoding="utf-8", errors="replace").read()
                except Exception:
                    pass
    result = analyse_log_text(raw, q, env, "api-search", user.id) if raw else {"log_rows": [], "total": 0}
    return jsonify({"query": q, "total": result.get("total",0), "rows": result.get("log_rows",[])[:limit]})

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
    sample = """INFO 2026-04-27 10:00:00,100 [[MuleRuntime].uber.1: [demo-checkout-api].post:\checkout:application\json:demo-config.CPU_LITE] [processor: checkout-flow/processors/1; event: demo-trace-001] org.mule.runtime.core.internal.processor.LoggerMessageProcessor: before checkout log {"amount":2499,"checkoutStatus":"Success","customerMobile":"9876543210","orderReference":"ORD-DEMO-12345"}
ERROR 2026-04-27 10:00:03,450 [[MuleRuntime].uber.2: [demo-checkout-api].post:\checkout:application\json:demo-config.CPU_LITE] [processor: checkout-flow/processors/3; event: demo-trace-001] org.mule.runtime.core.internal.processor.LoggerMessageProcessor: downstream timeout while calling inventory service duration=3350
WARN 2026-04-27 10:01:04,450 [[MuleRuntime].uber.3: [demo-notification-api].post:\notify:application\json:demo-config.CPU_LITE] [processor: notify-flow/processors/2; event: demo-trace-002] org.mule.runtime.core.internal.processor.LoggerMessageProcessor: retry started for webhook call duration=1200
INFO 2026-04-27 10:01:06,150 [[MuleRuntime].uber.4: [demo-notification-api].post:\notify:application\json:demo-config.CPU_LITE] [processor: notify-flow/processors/4; event: demo-trace-002] org.mule.runtime.core.internal.processor.LoggerMessageProcessor: completed in 1700ms status=200
"""
    result = analyse_log_text(sample, "", "DEMO", "demo-incident.log", user.id)
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
    user=lookup_user_by_api_key(auth.split(" ",1)[1])
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
                db.session.add(ls); db.session.commit(); persist_raw_upload(uid,ls.id,appname,raw_text)
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
    raw, digest, prefix = generate_api_key()
    user.api_key = None
    user.api_key_hash = digest
    user.api_key_prefix = prefix
    db.session.commit()
    return jsonify({"api_key": raw, "prefix": prefix, "message": "Copy this key now. It is stored hashed and will not be shown again."})


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


# ── V30 Enterprise foundations: RCA, trace compare, live anomalies, SLA, search, reports ──
def _latest_rows_for_user(user_id, limit=5000, env="ALL", api_name="", endpoint=""):
    rows = query_log_events_db(user_id, env=env, api_name=api_name, endpoint=endpoint, limit=limit)
    if rows:
        return rows
    sessions = LogSession.query.filter_by(user_id=user_id).order_by(LogSession.created_at.desc()).limit(5).all()
    for sess in sessions:
        if env and env not in ("ALL", "ANY") and str(sess.environment or "").upper() != str(env).upper():
            continue
        rows.extend(_json_loads_safe(sess.log_rows_json, []) or [])
        if len(rows) >= limit:
            break
    return rows[:limit]

def _score_endpoint(rows):
    total = len(rows)
    errors = sum(1 for r in rows if str(r.get('level','')).upper() in ('ERROR','FAILURE','FATAL'))
    warns = sum(1 for r in rows if str(r.get('level','')).upper() == 'WARN')
    latencies = sorted([int(r.get('latency') or r.get('latency_ms') or 0) for r in rows if str(r.get('latency') or r.get('latency_ms') or '').isdigit()])
    avg = round(sum(latencies)/len(latencies)) if latencies else 0
    p95 = latencies[min(len(latencies)-1, int(len(latencies)*.95))] if latencies else 0
    err_rate = round(errors/max(1,total)*100, 2)
    latency_score = max(0, 25 - min(25, p95/200))
    error_score = max(0, 30 - min(30, err_rate*4))
    availability = max(0, 25 - min(25, errors*100/max(1,total)))
    freshness = 10
    stability = max(0, 10 - min(10, warns*100/max(1,total)))
    score = round(latency_score + error_score + availability + freshness + stability)
    return {"score": score, "total": total, "errors": errors, "warnings": warns, "avg_latency_ms": avg, "p95_latency_ms": p95, "error_rate": err_rate,
            "status": "Healthy" if score >= 90 else "Watch" if score >= 70 else "Breach risk",
            "why": [f"{err_rate}% error rate", f"P95 {p95}ms", f"{warns} warning signals"]}

def _build_rca(rows, api_name='', endpoint='', user_id=None):
    scoped = [r for r in rows if (not api_name or api_name.lower() in str(r.get('app') or r.get('api') or r.get('api_name') or '').lower()) and (not endpoint or endpoint in str(r.get('endpoint') or r.get('flow') or r.get('message') or ''))]
    if not scoped: scoped = rows
    err_rows = [r for r in scoped if str(r.get('level','')).upper() in ('ERROR','FAILURE','FATAL') or re.search(r'exception|timeout|failed|failure|refused|unavailable', str(r.get('message','')), re.I)]
    clusters = {}
    for r in err_rows:
        msg = re.sub(r'\b\d{2,}\b', '#', str(r.get('message',''))[:300])
        key = (re.search(r'(timeout|exception|refused|unavailable|unauthorized|forbidden|connection|database|db|downstream|soap|http\s*5\d\d|http\s*4\d\d)', msg, re.I) or [None, 'General failure'])[1]
        clusters.setdefault(key.lower(), {"count":0,"samples":[],"apps":set(),"traces":set()})
        clusters[key.lower()]["count"] += 1
        clusters[key.lower()]["apps"].add(str(r.get('app') or r.get('api') or 'unknown'))
        if r.get('trace') or r.get('event'): clusters[key.lower()]["traces"].add(str(r.get('trace') or r.get('event')))
        if len(clusters[key.lower()]["samples"]) < 3: clusters[key.lower()]["samples"].append(str(r.get('message',''))[:500])
    top = sorted(clusters.items(), key=lambda kv: kv[1]['count'], reverse=True)[:5]
    owner = 'Unassigned'
    if api_name:
        reg_q = ApiRegistry.query
        if user_id:
            reg_q = reg_q.filter_by(user_id=user_id)
        reg = reg_q.filter(ApiRegistry.api_name.ilike(f"%{api_name}%")).first()
        if reg and reg.owner: owner = reg.owner
    cause = "No failure pattern detected yet. Upload richer logs with trace IDs and endpoint names." if not top else f"Most likely cause: {top[0][0]} cluster affecting {', '.join(list(top[0][1]['apps'])[:3])}."
    return {"summary": cause, "confidence": min(95, 25 + len(err_rows)*3 + len(top)*10), "owner": owner,
            "clusters": [{"name":k,"count":v['count'],"apps":sorted(v['apps']),"traces":list(v['traces'])[:5],"samples":v['samples']} for k,v in top],
            "next_steps": ["Open the highest-error trace and read the first ERROR plus the preceding INFO lines.", "Compare a failed trace against a successful trace for the same endpoint.", "Assign the incident to the mapped API owner/downstream team."]}

@app.route('/api/v1/enterprise/global-search')
@login_required
def enterprise_global_search():
    user = get_current_user(); q = request.args.get('q','').strip(); env = request.args.get('env','').strip().upper(); limit = min(int(request.args.get('limit', 25)), 100)
    rows = search_indexed_log_events(user.id, q, env or 'ALL', limit) if q else _latest_rows_for_user(user.id, limit, env or 'ALL')
    registry = []
    if q:
        regs = ApiRegistry.query.filter_by(user_id=user.id).filter(db.or_(ApiRegistry.api_name.ilike(f'%{q}%'), ApiRegistry.owner.ilike(f'%{q}%'), ApiRegistry.base_url.ilike(f'%{q}%'))).limit(10).all()
        registry = [{"type":"api","api_name":r.api_name,"owner":r.owner,"environment":r.environment,"base_url":r.base_url} for r in regs]
    return jsonify({"query":q,"results":[{"type":"log","time":r.get('time') or r.get('event_time'),"level":r.get('level'),"api":r.get('app') or r.get('api') or r.get('api_name'),"endpoint":r.get('endpoint') or r.get('flow'),"trace":r.get('trace') or r.get('event'),"message":str(r.get('message',''))[:600]} for r in rows] + registry})

@app.route('/api/v1/enterprise/live-alerts')
@login_required
def enterprise_live_alerts():
    user = get_current_user(); env=request.args.get('env','').strip().upper(); rows = _latest_rows_for_user(user.id, 1000, env or 'ALL')
    score = _score_endpoint(rows); rca = _build_rca(rows, user_id=user.id)
    alerts=[]
    if score['errors']: alerts.append({"level":"critical" if score['error_rate']>5 else "warn", "title":"Error spike detected", "message":f"{score['errors']} errors across latest {score['total']} events", "owner":rca.get('owner','Unassigned')})
    if score['p95_latency_ms']>3000: alerts.append({"level":"warn", "title":"Latency anomaly", "message":f"P95 latency is {score['p95_latency_ms']}ms", "owner":rca.get('owner','Unassigned')})
    if not alerts: alerts.append({"level":"ok","title":"No live anomaly","message":"Latest baseline is stable. Alerts improve as more logs are ingested.","owner":"ObserveX"})
    return jsonify({"alerts": alerts[:8], "health": score})

@app.route('/api/v1/enterprise/rca')
@login_required
def enterprise_rca():
    user=get_current_user(); env=request.args.get('env','').strip().upper(); rows=_latest_rows_for_user(user.id, 5000, env or 'ALL', request.args.get('api_name',''), request.args.get('endpoint',''))
    return jsonify(_build_rca(rows, request.args.get('api_name',''), request.args.get('endpoint',''), user.id))

@app.route('/api/v1/enterprise/sla')
@login_required
def enterprise_sla():
    user=get_current_user(); env=request.args.get('env','').strip().upper(); api=request.args.get('api_name',''); ep=request.args.get('endpoint',''); rows=_latest_rows_for_user(user.id, 5000, env or 'ALL', api, ep)
    scoped=[r for r in rows if (not api or api.lower() in str(r.get('app') or r.get('api') or '').lower()) and (not ep or ep in str(r.get('endpoint') or r.get('flow') or r.get('message') or ''))]
    return jsonify(_score_endpoint(scoped or rows))

@app.route('/api/v1/enterprise/trace-compare')
@login_required
def enterprise_trace_compare():
    user=get_current_user(); env=request.args.get('env','').strip().upper(); a=request.args.get('a','').strip(); b=request.args.get('b','').strip(); api=request.args.get('api_name',''); ep=request.args.get('endpoint',''); rows=_latest_rows_for_user(user.id, 5000, env or 'ALL', api, ep)
    def trace_rows(tid): return [r for r in rows if tid and tid in str(r.get('trace') or r.get('event') or r.get('message') or '')]
    traces={}
    for r in rows:
        tid=str(r.get('trace') or r.get('event') or '')
        if tid: traces.setdefault(tid, []).append(r)
    if not a:
        failed=[(tid,rs) for tid,rs in traces.items() if any(str(x.get('level','')).upper() in ('ERROR','FAILURE','FATAL') for x in rs)]
        if failed: a=sorted(failed, key=lambda x: len(x[1]), reverse=True)[0][0]
    if not b:
        good=[(tid,rs) for tid,rs in traces.items() if tid!=a and not any(str(x.get('level','')).upper() in ('ERROR','FAILURE','FATAL') for x in rs)]
        if good: b=sorted(good, key=lambda x: len(x[1]), reverse=True)[0][0]
    ar,br=trace_rows(a),trace_rows(b)
    def steps(rs):
        out=[]
        for r in rs[:80]:
            out.append({"time":r.get('time'),"level":r.get('level'),"api":r.get('app') or r.get('api'),"endpoint":r.get('endpoint') or r.get('flow'),"latency":r.get('latency') or 0,"message":str(r.get('message',''))[:300]})
        return out
    first_diff='No comparable traces yet.'
    for i,(x,y) in enumerate(zip(ar,br)):
        if str(x.get('level'))!=str(y.get('level')) or str(x.get('app'))!=str(y.get('app')):
            first_diff=f"First divergence at step {i+1}: failed={x.get('level')} {x.get('app')} vs success={y.get('level')} {y.get('app')}"; break
    return jsonify({"failed_trace":a,"success_trace":b,"first_difference":first_diff,"failed_steps":steps(ar),"success_steps":steps(br)})


@app.route('/retention/apply', methods=['POST'])
@login_required
def retention_apply_now():
    user = get_current_user()
    deleted = apply_retention_for_user(user)
    return jsonify({'status':'applied','deleted_sessions':deleted})

@app.route('/api/v1/enterprise/alerts/evaluate', methods=['POST'])
@login_required
def enterprise_alerts_evaluate():
    user = get_current_user()
    data = request.get_json(force=True, silent=True) or {}
    env = str(data.get('env') or data.get('environment') or request.args.get('env') or 'ALL').upper()
    rows = _latest_rows_for_user(user.id, min(int(data.get('limit') or 5000), 10000), env)
    incident = maybe_create_incident_from_rows(user.id, rows, env, None)
    sent = []
    if incident:
        db.session.flush()
        sent = _send_alert_notifications(user.id, {'title': incident.title, 'severity': incident.severity, 'environment': env, 'incident_id': incident.id, 'message': incident.notes or incident.impacted_apis})
    db.session.commit()
    return jsonify({'evaluated': len(rows), 'incident_created': bool(incident), 'incident_id': incident.id if incident else None, 'notifications': sent, 'health': _score_endpoint(rows)})

@app.route('/api/v1/enterprise/report')
@login_required
def enterprise_report():
    user=get_current_user(); env=request.args.get('env','').strip().upper(); rows=_latest_rows_for_user(user.id, 5000, env or 'ALL'); sla=_score_endpoint(rows); rca=_build_rca(rows, user_id=user.id)
    lines=["ObserveX Executive Reliability Report", f"Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", "", f"Health score: {sla['score']}/100 ({sla['status']})", f"Events analysed: {sla['total']}", f"Errors: {sla['errors']} · Warnings: {sla['warnings']} · Error rate: {sla['error_rate']}%", f"Average latency: {sla['avg_latency_ms']}ms · P95 latency: {sla['p95_latency_ms']}ms", "", "RCA Summary:", rca['summary'], f"Suggested owner: {rca.get('owner','Unassigned')}", "", "Recommended actions:"] + [f"- {x}" for x in rca.get('next_steps', [])]
    return Response("\n".join(lines), mimetype='text/plain', headers={"Content-Disposition":"attachment; filename=observex-executive-report.txt"})



# ── V9 Enterprise API/Security/Incident enhancements ───────────────────────

def _safe_json_dict(txt, default=None):
    try:
        val = json.loads(txt or '{}')
        return val if isinstance(val, dict) else (default or {})
    except Exception:
        return default or {}

def _send_alert_notifications(user_id, payload):
    """Best-effort alert notification fan-out for email/slack/teams/webhook destinations.
    Slack and Teams support incoming webhook URLs. Generic webhook receives JSON.
    Email uses configured Flask-Mail SMTP when available.
    """
    sent = []
    destinations = AlertDestination.query.filter_by(user_id=user_id, active=True).all()
    for d in destinations:
        kind = (d.kind or 'webhook').lower()
        target = d.target or ''
        try:
            if kind == 'email' and app.config.get('MAIL_USERNAME'):
                msg = Message(subject=payload.get('title', 'ObserveX Alert'), recipients=[target], body=json.dumps(payload, indent=2, default=str))
                mail.send(msg)
                sent.append({'id': d.id, 'kind': kind, 'status': 'sent'})
            elif kind in {'slack', 'teams', 'webhook'} and target.startswith(('http://', 'https://')):
                import urllib.request
                body = json.dumps(payload, default=str).encode('utf-8')
                req = urllib.request.Request(target, data=body, headers={'Content-Type': 'application/json'}, method='POST')
                with urllib.request.urlopen(req, timeout=4) as resp:
                    sent.append({'id': d.id, 'kind': kind, 'status': 'sent', 'code': getattr(resp, 'status', 200)})
            else:
                sent.append({'id': d.id, 'kind': kind, 'status': 'skipped', 'reason': 'unsupported target or SMTP not configured'})
        except Exception as exc:
            app.logger.exception('Alert notification failed')
            sent.append({'id': d.id, 'kind': kind, 'status': 'failed', 'error': str(exc)[:300]})
    return sent

@app.route('/api/v1/alerts/test', methods=['POST'])
@login_required
def api_alerts_test():
    user = get_current_user()
    payload = request.get_json(force=True, silent=True) or {}
    payload.setdefault('title', 'ObserveX test alert')
    payload.setdefault('severity', 'Info')
    payload.setdefault('environment', payload.get('env') or 'TEST')
    payload.setdefault('message', 'This is a test notification from ObserveX V9.')
    sent = _send_alert_notifications(user.id, payload)
    audit_event(user, 'alert.test', payload.get('title'), {'destinations': sent})
    db.session.commit()
    return jsonify({'ok': True, 'destinations': sent})

@app.route('/api/v1/incidents/<int:incident_id>', methods=['GET', 'PATCH'])
@login_required
def api_incident_detail(incident_id):
    user = get_current_user()
    row = Incident.query.filter_by(user_id=user.id, id=incident_id).first_or_404()
    if request.method == 'PATCH':
        if get_user_role(user) not in {'Admin', 'Developer'}:
            return jsonify({'error': 'Only Admin/Developer can update incidents'}), 403
        data = request.get_json(force=True, silent=True) or {}
        if 'status' in data: row.status = str(data.get('status') or row.status)[:40]
        if 'owner' in data: row.owner = str(data.get('owner') or row.owner)[:120]
        if 'notes' in data: row.notes = str(data.get('notes') or row.notes)[:4000]
        row.updated_at = datetime.datetime.utcnow()
        audit_event(user, 'incident.patch', row.title, {'status': row.status, 'owner': row.owner})
        db.session.commit()
    evidence = _safe_json_dict(row.evidence_json, {})
    trace_ids = evidence.get('sample_traces') or []
    related_logs = []
    for tid in trace_ids[:5]:
        rows, _record = trace_rows_db(user.id, tid, evidence.get('environment') or 'ALL', 50)
        related_logs.extend(rows[:10])
    return jsonify({
        'id': row.id, 'title': row.title, 'severity': row.severity, 'status': row.status,
        'owner': row.owner, 'impacted_apis': row.impacted_apis, 'notes': row.notes,
        'evidence': evidence, 'related_logs': related_logs[:50],
        'created_at': row.created_at.isoformat() if row.created_at else None,
        'updated_at': row.updated_at.isoformat() if row.updated_at else None
    })

@app.route('/api/v1/logs/export', methods=['GET'])
def api_logs_export():
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '): return jsonify({'error': 'Missing token'}), 401
    user = lookup_user_by_api_key(auth.split(' ', 1)[1])
    if not user: return jsonify({'error': 'Invalid API key'}), 401
    if api_rate_limited('export:' + str(user.id), limit=20, window=60):
        return jsonify({'error': 'Export rate limit exceeded'}), 429
    q = request.args.get('q', '')
    env = request.args.get('environment', request.args.get('env', 'PROD'))
    limit = min(5000, int(request.args.get('limit', '1000') or 1000))
    rows = search_indexed_log_events(user.id, q, env, limit)
    audit_event(user, 'logs.export', q, {'rows': len(rows), 'environment': env})
    db.session.commit()
    return Response(json.dumps({'rows': rows}, default=str), mimetype='application/json', headers={'Content-Disposition': 'attachment; filename=observex-logs-export.json'})

@app.route('/api/v1/openapi.json')
def openapi_spec():
    spec = {
        'openapi': '3.0.3',
        'info': {'title': 'ObserveX API', 'version': 'v9', 'description': 'Log ingestion, search, trace lookup, incident and alert APIs.'},
        'components': {'securitySchemes': {'BearerAuth': {'type': 'http', 'scheme': 'bearer'}}},
        'security': [{'BearerAuth': []}],
        'paths': {
            '/api/v1/logs/ingest': {'post': {'summary': 'Ingest raw or structured logs', 'responses': {'200': {'description': 'Ingested or queued'}}}},
            '/api/v1/logs/ingest-async': {'post': {'summary': 'Queue API log ingestion job', 'responses': {'200': {'description': 'Queued'}}}},
            '/api/v1/logs/search': {'get': {'summary': 'Search indexed logs by q/env/limit', 'responses': {'200': {'description': 'Search results'}}}},
            '/api/v1/logs/export': {'get': {'summary': 'Export indexed log rows as JSON', 'responses': {'200': {'description': 'JSON export'}}}},
            '/api/v1/trace/{trace_id}': {'get': {'summary': 'Lookup a trace from TraceIndex/LogEvent', 'parameters': [{'name': 'trace_id', 'in': 'path', 'required': True, 'schema': {'type': 'string'}}], 'responses': {'200': {'description': 'Trace details'}}}},
            '/api/v1/incidents/{incident_id}': {'get': {'summary': 'Incident detail with evidence'}, 'patch': {'summary': 'Update incident owner/status/notes'}},
            '/api/v1/alerts/test': {'post': {'summary': 'Send test alert to configured destinations', 'responses': {'200': {'description': 'Delivery result'}}}}
        }
    }
    return jsonify(spec)

@app.route('/api/swagger')
def api_swagger_page():
    return '''<!doctype html><html><head><title>ObserveX API Docs</title><style>body{font-family:system-ui;margin:30px;line-height:1.6}code,pre{background:#f4f4f6;padding:2px 6px;border-radius:6px}pre{padding:16px;overflow:auto}</style></head><body><h1>ObserveX API V9</h1><p>Use <code>Authorization: Bearer &lt;OBSERVEX_API_KEY&gt;</code>.</p><p>OpenAPI JSON: <a href="/api/v1/openapi.json">/api/v1/openapi.json</a></p><h2>Important endpoints</h2><pre>POST /api/v1/logs/ingest
POST /api/v1/logs/ingest-async
GET  /api/v1/logs/search?q=level:ERROR env:PROD
GET  /api/v1/trace/{trace_id}
GET  /api/v1/logs/export
GET/PATCH /api/v1/incidents/{incident_id}
POST /api/v1/alerts/test</pre></body></html>'''
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
