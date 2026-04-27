import os, re, json, hashlib, secrets, datetime, threading
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, jsonify, flash, make_response
)
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps

app = Flask(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///observex.db"
).replace("postgres://", "postgresql://")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_UPLOAD_MB", "500")) * 1024 * 1024  # default 500 MB

# Mail (configure via env vars in Railway)
app.config["MAIL_SERVER"]   = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
app.config["MAIL_PORT"]     = int(os.environ.get("MAIL_PORT", 587))
app.config["MAIL_USE_TLS"]  = True
app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME", "")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD", "")
app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("MAIL_USERNAME", "noreply@observex.io")

db   = SQLAlchemy(app)
mail = Mail(app)

ALLOWED_EXT = {"log", "txt", "json"}

# Railway volume/persistent storage. Mount a Railway volume and set OBSERVEX_DATA_DIR=/data.
DATA_DIR = os.environ.get("OBSERVEX_DATA_DIR", "/data")
UPLOAD_DIR = os.path.join(DATA_DIR, "observex_uploads")
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

class CustomEnvironment(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    name       = db.Column(db.String(40), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    __table_args__ = (db.UniqueConstraint("user_id", "name", name="uq_user_environment"),)

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
        "customerId", "applicationNo", "paymentId", "bbpsId", "receiptNumber",
        "transactionId", "gatewayTransactionId", "upiId", "vpa", "cardNumber", "ifsc"
    ]
    key_alt = "|".join(map(re.escape, sensitive_keys))
    masked = re.sub(rf"(?i)(\"(?:{key_alt})\"\s*:\s*\")([^\"]+)(\")", r"\1[MASKED]\3", masked)
    masked = re.sub(rf"(?i)(\b(?:{key_alt})\b\s*[=:]\s*['\"]?)([A-Za-z0-9@._\- /]+)", r"\1[MASKED]", masked)

    # Long numeric identifiers likely to be account/loan/reference numbers.
    masked = re.sub(r"\b(?:TR|PP|BD|FS|GLB|APPL|APPT)[A-Z0-9]{6,}\b", "[MASKED_ID]", masked)

    return masked


def persist_raw_upload(user_id: int, session_id: int, filename: str, raw: str):
    """Persist masked raw logs to Railway volume for audit/re-open without keeping sensitive values."""
    safe_name = secure_filename(filename or "upload.log")[:120]
    user_dir = os.path.join(UPLOAD_DIR, str(user_id))
    os.makedirs(user_dir, exist_ok=True)
    path = os.path.join(user_dir, f"session-{session_id}-{safe_name}.masked.log")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(mask_secrets(raw))
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
        rows.append({
            "line_no": rec.get("line_no"), "time": extract_time(line, f"line {rec.get('line_no')}"), "env": env,
            "file": current_file, "level": detect_level(line), "app": app, "trace": trace,
            "event": trace, "flow": flow, "status": status, "latency": int(lat) if str(lat).isdigit() else 0,
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
        r'\bsourceModule"?\s*:\s*"([^"]+)"', r'\bpaymentApp"?\s*:\s*"([^"]+)"'
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
    return {
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
        "query_help": "Use env:PROD app:s-htmltopdf-api level:ERROR trace:<id> message:\"otp success\" latency>3000 date:2026-04-11"
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
    if get_current_user() is not None:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

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

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name  = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        pwd   = request.form.get("password", "")
        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "error")
        elif len(pwd) < 8:
            flash("Password must be at least 8 characters.", "error")
        else:
            user = User(name=name, email=email,
                        password_hash=generate_password_hash(pwd))
            db.session.add(user)
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
    user = get_current_user()
    recent = LogSession.query.filter_by(user_id=user.id)                             .order_by(LogSession.created_at.desc()).limit(10).all()
    alerts = AlertRule.query.filter_by(user_id=user.id).all()
    return render_template("dashboard.html", user=user, recent=recent, alerts=alerts, environments=get_user_environments(user))

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

        result = analyse_log_text(raw, query, env, fname)
        user = get_current_user()
        if user is None:
            return jsonify({"error": "Session expired. Please login again."}), 401
        ls = LogSession(user_id=user.id, environment=env, filename=fname,
                        total_lines=result["total"], error_count=result["errors"],
                        warn_count=result["warns"], avg_latency=result["latency"],
                        apps_found=",".join(result["apps"]))
        db.session.add(ls)
        db.session.commit()
        try:
            persist_raw_upload(user.id, ls.id, fname, raw)
        except Exception:
            app.logger.exception("Could not persist upload to volume")
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
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "Missing token"}), 401
    key  = auth.split(" ", 1)[1]
    user = User.query.filter_by(api_key=key).first()
    if not user:
        return jsonify({"error": "Invalid API key"}), 401

    data  = request.get_json(force=True, silent=True) or {}
    env   = data.get("environment", "PROD")
    raw   = data.get("logs", "")
    app_n = data.get("application", "api-source")

    if not raw:
        return jsonify({"error": "logs field required"}), 400

    result = analyse_log_text(raw, "", env, app_n)
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
    db.session.commit()
    try:
        persist_raw_upload(user.id, ls.id, app_n, raw)
    except Exception:
        app.logger.exception("Could not persist API ingestion to volume")
    return jsonify({"status": "ok", "session_id": ls.id, "stored": True, **result})

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
        name = re.sub(r"[^A-Za-z0-9_-]", "", (request.args.get("name") or "").upper())[:40]
        env = CustomEnvironment.query.filter_by(user_id=user.id, name=name).first()
        if env:
            db.session.delete(env)
            db.session.commit()
        return jsonify({"environments": get_user_environments(user)})
    return jsonify({"environments": get_user_environments(user), "defaults": DEFAULT_ENVIRONMENTS})


@app.route("/api/docs")
@login_required
def api_docs():
    user = get_current_user()
    return jsonify({
        "auth": "Authorization: Bearer <api_key>",
        "base_url": request.host_url.rstrip("/"),
        "ingest": {
            "method": "POST",
            "path": "/api/v1/logs/ingest",
            "request": {
                "environment": "PROD",
                "application": "s-paymentengine-api",
                "logs": "INFO 2026-04-25 14:51:17 ..."
            },
            "success_response": {"status":"ok", "session_id":123, "stored": True, "errors":0, "warns":0},
            "failure_responses": {"401":"Missing/invalid API key", "400":"logs field required", "413":"payload exceeds MAX_UPLOAD_MB"},
            "notes": [
                "Logs are masked for JWT, tokens, PAN, Aadhaar, mobile, customer names, loan/account/payment identifiers before returning to UI.",
                "Set OBSERVEX_DATA_DIR=/data when using Railway Volume to persist masked uploads.",
                "For 500MB+ production ingestion, prefer direct API/S3 streaming over browser upload."
            ]
        }
    })

# ── Profile / API key ─────────────────────────────────────────────────────────
@app.route("/profile/apikey", methods=["POST"])
@login_required
def rotate_api_key():
    user = get_current_user()
    if user is None:
        return jsonify({"error": "Session expired. Please login again."}), 401
    user.api_key = secrets.token_hex(32)
    db.session.commit()
    return jsonify({"api_key": user.api_key})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
