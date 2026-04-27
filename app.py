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
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_UPLOAD_MB", "100")) * 1024 * 1024  # default 100 MB

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
    if re.search(r"\b(ERROR|FATAL|SEVERE)\b|exception|failed|timeout|gateway timeout|bad request|\b5\d\d\b", line, re.I):
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

def build_log_rows(lines, env, filename=""):
    rows=[]
    current_app=""; current_file=filename
    for idx,line in enumerate(lines):
        fm = re.search(r"--- FILE:\s*([^\n]+?)\s*---", line)
        if fm:
            current_file=fm.group(1).strip(); continue
        app = extract_first([
            r"\[([a-zA-Z][a-zA-Z0-9_-]*(?:api|API)[a-zA-Z0-9_-]*)\]",
            r'"ApplicationName"\s*:\s*"([^"\n]+)"',
            r"(?:app|application|service|applicationName)\s*[=:]\s*['\"]?([a-zA-Z0-9_.-]+)"
        ], line, current_app or "unknown")
        if app != "unknown": current_app=app
        trace = extract_trace_id(line)
        status = extract_first([r'"HttpStatus"\s*:\s*(\d{3})', r"(?:status|statusCode|httpStatus)\s*[=:]\s*(\d{3})", r"\b(5\d\d|4\d\d|2\d\d)\b"], line, "")
        lat = extract_first([r"(?:latency|duration|timeTaken|elapsed)\s*[=: ]+([0-9]+)", r"completed in\s+([0-9]+)\s*ms"], line, "")
        flow = extract_first([r"processor:\s*([^;\]]+)", r'"FlowName"\s*:\s*"([^"]+)"', r"\]\.([a-zA-Z0-9_-]+flow)\."], line, "")
        rows.append({
            "line_no": idx+1, "time": extract_time(line, f"line {idx+1}"), "env": env,
            "file": current_file, "level": detect_level(line), "app": app, "trace": trace,
            "event": trace, "flow": flow, "status": status, "latency": int(lat) if str(lat).isdigit() else 0,
            "message": line[:1200]
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
    all_lines = [l for l in raw.splitlines() if l.strip()]
    detected_env = infer_environment(raw[:5000], env)
    all_rows = build_log_rows(all_lines, detected_env, filename)
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
            r"(JWT|token|timeout|Salesforce|\.Net pdf|GoogleSecops|Gupshup|OTP|connection|bad request|gateway)"
        ], msg, "General error")
        top_errors[key]=top_errors.get(key,0)+1
    top_errors=sorted(top_errors.items(), key=lambda x:x[1], reverse=True)[:10]
    tag_rules={
        'JWT / Token': r'jwt|token', 'Salesforce': r'salesforce|sfdc', '.NET PDF': r'\.net pdf|pdf api|htmltopdf',
        'Google SecOps': r'googlesecops|google secops', 'OTP / Gupshup': r'otp|gupshup|sms',
        'Slow API': r'latency|duration|timeTaken|slow|timeout', 'External Dependency': r'salesforce|gupshup|\.net|google'
    }
    smart_tags=[name for name,pat in tag_rules.items() if re.search(pat, joined, re.I)]
    deps=[name for name,pat in {'Salesforce':r'salesforce|sfdc','.NET PDF API':r'\.net pdf|pdf api','Google SecOps':r'googlesecops|google secops','Gupshup':r'gupshup|otp|sms'}.items() if re.search(pat, raw, re.I)]
    findings = [
        {"label": f"{detected_env}: {len(errors)} error line(s), {len(warns)} warning line(s)", "type": "error" if errors else ("warn" if warns else "ok")},
        {"label": f"Applications detected: {', '.join(apps[:8]) or 'none'}", "type": "ok" if apps else "warn"},
        {"label": f"Avg {avg_lat}ms · P95 {p95}ms · P99 {p99}ms", "type": "warn" if p95 > 3000 else "info"},
        {"label": f"Trace/Event IDs found: {len(traces)}", "type": "info"},
    ]
    suggestions=[]
    if len(apps)>1: suggestions.append("Use Logs Search > Application filter to analyse each API separately.")
    if errors: suggestions.append("Open the first failing trace/event in Trace Explorer and check the previous 10 log lines.")
    if p95>3000: suggestions.append("Latency hotspot detected. Check external dependency calls and timeout/retry configuration.")
    if 'JWT / Token' in smart_tags: suggestions.append("JWT/token logs detected. Mask secrets before sharing screenshots or reports.")
    if not suggestions: suggestions.append("No major hotspot detected. Continue with environment/date/app filtering for validation.")
    score=max(0, min(100, 100 - min(50, error_rate*5) - min(25, warn_rate*2) - (15 if p95>3000 else 0)))
    return {
        "environment": detected_env, "total": total, "original_total": len(all_rows), "errors": len(errors), "warns": len(warns),
        "latency": avg_lat, "p95": p95, "p99": p99, "error_rate": error_rate, "warn_rate": warn_rate,
        "apps": apps, "app_counts": app_counts, "traces": traces, "events": traces, "statuses": status_counts,
        "top_errors": top_errors, "findings": findings, "suggestions": suggestions, "smart_tags": smart_tags,
        "dependencies": deps, "health_score": round(score), "log_rows": rows[:1200],
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
    return render_template("dashboard.html", user=user, recent=recent, alerts=alerts)

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
    return jsonify({"status": "ok", "session_id": ls.id, **result})

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
@app.route("/history")
@login_required
def history():
    user = get_current_user()
    if user is None:
        return jsonify({"error": "Session expired. Please login again."}), 401
    uid = user.id
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
