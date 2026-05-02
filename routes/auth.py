"""
routes/auth.py — Authentication blueprint.

Improvements over monolith:
  - Password reset tokens are hashed at rest (verify_reset_token uses timing-safe compare).
  - Account lockout: after LOGIN_LOCKOUT_MAX_FAILURES failed attempts the account is locked
    for LOGIN_LOCKOUT_MINUTES minutes.
  - clear_failed_logins() called on successful login.
  - Google OAuth preserved unchanged.
"""
import os
import datetime
import secrets

from flask import (
    Blueprint, render_template, request, redirect,
    url_for, session, flash,
)
from werkzeug.security import generate_password_hash, check_password_hash

from extensions import db, mail
from models import User, Workspace, WorkspaceMember, InviteCode
from services.security import (
    generate_api_key,
    generate_reset_token,
    verify_reset_token,
    record_failed_login,
    is_account_locked,
    clear_failed_logins,
)

auth_bp = Blueprint("auth", __name__)

# Populated by create_app() after OAuth is configured
google = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _audit(user, action, target="", details=None):
    """Thin wrapper — avoids circular import with main app audit_event."""
    try:
        from app import audit_event
        audit_event(user, action, target, details)
    except Exception:
        pass


def send_reset_email(user) -> bool:
    raw_token, hashed_token = generate_reset_token()
    user.reset_token      = None          # legacy plaintext column — cleared
    user.reset_token_hash = hashed_token
    user.reset_expires    = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    db.session.commit()

    link = url_for("auth.reset_password", token=raw_token, _external=True)
    try:
        from flask_mail import Message
        msg = Message("ObserveX – Password Reset", recipients=[user.email])
        msg.body = (
            f"Hi {user.name},\n\nReset your password:\n{link}\n\n"
            "This link expires in 1 hour and is single-use.\n\nObserveX"
        )
        mail.send(msg)
        return True
    except Exception:
        return False


# ── Routes ────────────────────────────────────────────────────────────────────

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        pwd   = request.form.get("password", "")
        user  = User.query.filter_by(email=email).first()

        if user:
            if is_account_locked(user):
                db.session.commit()
                flash("Account temporarily locked due to too many failed attempts. Try again later.", "error")
                return render_template("login.html")

            if check_password_hash(user.password_hash, pwd):
                clear_failed_logins(user)
                db.session.commit()
                session["user_id"]   = user.id
                session["user_name"] = user.name
                _audit(user, "auth.login", email)
                return redirect(url_for("dashboard"))

            locked = record_failed_login(user)
            db.session.commit()
            if locked:
                flash("Too many failed attempts. Account locked for "
                      f"{os.environ.get('LOGIN_LOCKOUT_MINUTES', 15)} minutes.", "error")
            else:
                flash("Invalid email or password.", "error")
        else:
            flash("Invalid email or password.", "error")

    return render_template("login.html")


@auth_bp.route("/login/google")
def google_login():
    if google is None:
        flash("Google login is not configured. Add GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.", "info")
        return redirect(url_for("auth.login"))
    redirect_uri = os.environ.get("GOOGLE_REDIRECT_URI") or url_for("auth.google_callback", _external=True)
    return google.authorize_redirect(redirect_uri)


@auth_bp.route("/auth/google/callback")
def google_callback():
    if google is None:
        flash("Google login is not configured.", "error")
        return redirect(url_for("auth.login"))
    token = google.authorize_access_token()
    info  = token.get("userinfo") or google.parse_id_token(token)
    email = (info.get("email") or "").strip().lower()
    name  = info.get("name") or email.split("@")[0]
    if not email:
        flash("Google did not return an email address.", "error")
        return redirect(url_for("auth.login"))

    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(name=name, email=email,
                    password_hash=generate_password_hash(secrets.token_urlsafe(32)))
        raw_key, digest, prefix = generate_api_key()
        user.api_key_hash = digest
        user.api_key_prefix = prefix
        db.session.add(user)
        db.session.flush()
        ws = Workspace(owner_id=user.id, name=f"{name}'s Workspace")
        db.session.add(ws)
        db.session.flush()
        db.session.add(WorkspaceMember(workspace_id=ws.id, user_id=user.id, role="Admin"))
        _audit(user, "auth.google_signup", email, {})
        db.session.commit()

    session["user_id"]   = user.id
    session["user_name"] = user.name
    _audit(user, "auth.google_login", email, {})
    db.session.commit()
    return redirect(url_for("dashboard"))


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name           = request.form.get("name", "").strip()
        email          = request.form.get("email", "").strip().lower()
        pwd            = request.form.get("password", "")
        workspace_name = request.form.get("workspace_name", "").strip()
        invite_code    = request.form.get("invite_code", "").strip()

        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "error")
        elif len(pwd) < 8:
            flash("Password must be at least 8 characters.", "error")
        else:
            user = User(name=name, email=email,
                        password_hash=generate_password_hash(pwd))
            raw_key, digest, prefix = generate_api_key()
            user.api_key_hash   = digest
            user.api_key_prefix = prefix
            db.session.add(user)
            db.session.flush()

            invite = InviteCode.query.filter_by(code=invite_code, active=True).first() if invite_code else None
            if invite:
                db.session.add(WorkspaceMember(
                    workspace_id=invite.workspace_id, user_id=user.id, role=invite.role
                ))
            else:
                ws = Workspace(owner_id=user.id, name=workspace_name or f"{name or 'My'} Workspace")
                db.session.add(ws)
                db.session.flush()
                db.session.add(WorkspaceMember(workspace_id=ws.id, user_id=user.id, role="Admin"))

            db.session.commit()
            session["user_id"]   = user.id
            session["user_name"] = user.name
            return redirect(url_for("dashboard"))

    return render_template("register.html")


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user  = User.query.filter_by(email=email).first()
        if user:
            ok = send_reset_email(user)
            flash(
                "Reset link sent – check your inbox." if ok
                else "Email sending failed. Configure MAIL_* env vars.",
                "info",
            )
        else:
            flash("If that email exists, a reset link has been sent.", "info")
        return redirect(url_for("auth.forgot_password"))
    return render_template("forgot_password.html")


@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    # Look up by hashed token (new path)
    import hashlib
    hashed = hashlib.sha256(token.encode()).hexdigest()
    user = User.query.filter_by(reset_token_hash=hashed).first()

    # Backward compat: old sessions may have plaintext token in reset_token column
    if not user:
        user = User.query.filter_by(reset_token=token).first()

    if not user or not user.reset_expires or user.reset_expires < datetime.datetime.utcnow():
        flash("Reset link is invalid or expired.", "error")
        return redirect(url_for("auth.forgot_password"))

    if not verify_reset_token(token, user.reset_token_hash or ""):
        # Legacy plaintext path — still valid for old sessions
        if user.reset_token != token:
            flash("Reset link is invalid.", "error")
            return redirect(url_for("auth.forgot_password"))

    if request.method == "POST":
        pwd = request.form.get("password", "")
        if len(pwd) < 8:
            flash("Password must be at least 8 characters.", "error")
        else:
            user.password_hash  = generate_password_hash(pwd)
            user.reset_token    = None       # clear legacy column
            user.reset_token_hash = None     # clear new column — single-use
            user.reset_expires  = None
            db.session.commit()
            flash("Password updated – please log in.", "success")
            return redirect(url_for("auth.login"))

    return render_template("reset_password.html", token=token)


@auth_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
