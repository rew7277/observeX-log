"""
models.py — ObserveX database models.
Extracted from app.py monolith as part of the modularisation refactor.
All models use Flask-SQLAlchemy via the shared `db` instance imported from extensions.py.
"""
import datetime
from extensions import db


class User(db.Model):
    id                = db.Column(db.Integer, primary_key=True)
    name              = db.Column(db.String(100), nullable=False)
    email             = db.Column(db.String(150), unique=True, nullable=False)
    password_hash     = db.Column(db.String(256), nullable=False)
    reset_token       = db.Column(db.String(100), nullable=True)
    reset_token_hash  = db.Column(db.String(128), nullable=True)   # NEW: hashed reset token
    reset_expires     = db.Column(db.DateTime, nullable=True)
    failed_login_count = db.Column(db.Integer, default=0)          # NEW: brute-force tracking
    locked_until      = db.Column(db.DateTime, nullable=True)       # NEW: account lockout
    created_at        = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    # api_key retained only for backward-compat migration; new keys use api_key_hash
    api_key           = db.Column(db.String(64), nullable=True)
    api_key_hash      = db.Column(db.String(128), nullable=True, index=True)
    api_key_prefix    = db.Column(db.String(12), nullable=True)
    api_key_last_used = db.Column(db.DateTime, nullable=True)


class LogSession(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey("user.id"), index=True)
    environment  = db.Column(db.String(20))
    filename     = db.Column(db.String(200))
    total_lines  = db.Column(db.Integer, default=0)
    error_count  = db.Column(db.Integer, default=0)
    warn_count   = db.Column(db.Integer, default=0)
    avg_latency  = db.Column(db.Integer, default=0)
    apps_found   = db.Column(db.Text, default="")
    # IMPORTANT: log_rows_json is DEPRECATED — rows are now stored in LogEvent.
    # This column is kept for backward compat with existing sessions and will be
    # removed in a future migration once all sessions reference LogEvent rows only.
    log_rows_json = db.Column(db.Text, default="[]")
    result_json   = db.Column(db.Text, default="{}")
    created_at    = db.Column(db.DateTime, default=datetime.datetime.utcnow)


class ApiFlowMap(db.Model):
    """Stores per-API, per-endpoint flow mapping extracted from uploaded logs."""
    id                = db.Column(db.Integer, primary_key=True)
    user_id           = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    session_id        = db.Column(db.Integer, db.ForeignKey("log_session.id"), nullable=False, index=True)
    api_name          = db.Column(db.String(200), nullable=False, index=True)
    environment       = db.Column(db.String(20), default="PROD", index=True)
    endpoint          = db.Column(db.String(300), default="")
    method            = db.Column(db.String(10), default="")
    flow_steps_json   = db.Column(db.Text, default="[]")
    architecture_json = db.Column(db.Text, default="{}")
    request_count     = db.Column(db.Integer, default=0)
    error_count       = db.Column(db.Integer, default=0)
    avg_latency_ms    = db.Column(db.Integer, default=0)
    sample_trace_id   = db.Column(db.String(120), default="")
    created_at        = db.Column(db.DateTime, default=datetime.datetime.utcnow)


class ApiRegistry(db.Model):
    """Master API inventory used by System Map and API dropdowns."""
    id                       = db.Column(db.Integer, primary_key=True)
    user_id                  = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    api_name                 = db.Column(db.String(200), nullable=False, index=True)
    environment              = db.Column(db.String(20), default="PROD", index=True)
    base_url                 = db.Column(db.String(400), default="")
    owner                    = db.Column(db.String(120), default="")
    status                   = db.Column(db.String(40), default="active")
    downstream_systems_json  = db.Column(db.Text, default="[]")
    manual_flow_nodes_json   = db.Column(db.Text, default="[]")
    last_seen_at             = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    created_at               = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    __table_args__ = (
        db.UniqueConstraint("user_id", "api_name", "environment", name="uq_api_registry_user_api_env"),
    )


class ApiEndpoint(db.Model):
    """Endpoint inventory under each API."""
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
    __table_args__ = (
        db.UniqueConstraint(
            "user_id", "api_name", "environment", "endpoint", "method",
            name="uq_api_endpoint_user_api_env_ep_method"
        ),
    )


class TraceIndex(db.Model):
    """Trace lookup table for fast Trace Explorer."""
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    session_id  = db.Column(db.Integer, db.ForeignKey("log_session.id"), nullable=False, index=True)
    trace_id    = db.Column(db.String(160), nullable=False, index=True)
    environment = db.Column(db.String(20), default="PROD", index=True)
    api_name    = db.Column(db.String(200), default="", index=True)
    endpoint    = db.Column(db.String(300), default="/")
    status      = db.Column(db.String(30), default="success")
    latency_ms  = db.Column(db.Integer, default=0)
    rows_json   = db.Column(db.Text, default="[]")
    created_at  = db.Column(db.DateTime, default=datetime.datetime.utcnow)


class LogEvent(db.Model):
    """
    Searchable parsed log rows. Primary store for all log data.
    Replaces log_rows_json on LogSession for new sessions.
    Composite index (user_id, environment, level) added for hot search path.
    """
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
    __table_args__ = (
        # Composite index for the global-search hot path
        db.Index("ix_log_event_user_env_level", "user_id", "environment", "level"),
        db.Index("ix_log_event_user_session",   "user_id", "session_id"),
    )


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
    user_id    = db.Column(db.Integer, db.ForeignKey("user.id"), index=True)
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
    __table_args__ = (
        db.UniqueConstraint("user_id", "name", name="uq_user_environment"),
    )


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
    role         = db.Column(db.String(30), default="Admin")
    created_at   = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    __table_args__ = (
        db.UniqueConstraint("workspace_id", "user_id", name="uq_workspace_user"),
    )


class AuditEvent(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
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
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    field_name  = db.Column(db.String(120), nullable=False)
    mask_type   = db.Column(db.String(40), default="full")
    enabled     = db.Column(db.Boolean, default=True)
    created_at  = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at  = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    __table_args__ = (
        db.UniqueConstraint("user_id", "field_name", name="uq_masking_rule_user_field"),
    )


class AlertDestination(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    kind       = db.Column(db.String(30), default="email")
    target     = db.Column(db.String(300), nullable=False)
    active     = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)


class SourceConnector(db.Model):
    id              = db.Column(db.Integer, primary_key=True)
    user_id         = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    kind            = db.Column(db.String(40), nullable=False)
    name            = db.Column(db.String(120), nullable=False)
    # config_json stores NON-SECRET config only.
    # Secrets must be stored encrypted in secret_json (Fernet-encrypted at rest).
    config_json     = db.Column(db.Text, default="{}")
    secret_json     = db.Column(db.Text, default="{}")   # NEW: encrypted secrets column
    active          = db.Column(db.Boolean, default=True)
    created_at      = db.Column(db.DateTime, default=datetime.datetime.utcnow)


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
    user_id     = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    source      = db.Column(db.String(60), default="file")
    filename    = db.Column(db.String(220), default="")
    status      = db.Column(db.String(30), default="queued")
    total_bytes = db.Column(db.Integer, default=0)
    total_lines = db.Column(db.Integer, default=0)
    error       = db.Column(db.Text, default="")
    session_id  = db.Column(db.Integer, db.ForeignKey("log_session.id"), nullable=True, index=True)
    progress    = db.Column(db.Integer, default=0)
    started_at  = db.Column(db.DateTime, nullable=True)
    finished_at = db.Column(db.DateTime, nullable=True)
    created_at  = db.Column(db.DateTime, default=datetime.datetime.utcnow)


class SharedReport(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    token      = db.Column(db.String(80), unique=True, nullable=False)
    revoked    = db.Column(db.Boolean, default=False)     # NEW: explicit revocation flag
    title      = db.Column(db.String(180), default="ObserveX RCA Report")
    content    = db.Column(db.Text, default="")
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)


class SavedSearch(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    title      = db.Column(db.String(140), nullable=False)
    query      = db.Column(db.String(500), default="")
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)


class DashboardWidget(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    title       = db.Column(db.String(140), nullable=False)
    widget_type = db.Column(db.String(80), default="Errors")
    config_json = db.Column(db.Text, default="{}")
    created_at  = db.Column(db.DateTime, default=datetime.datetime.utcnow)


class Incident(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    user_id       = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
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
    user_id     = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    action      = db.Column(db.String(80), default="search")
    duration_ms = db.Column(db.Integer, default=0)
    rows        = db.Column(db.Integer, default=0)
    bytes       = db.Column(db.Integer, default=0)
    created_at  = db.Column(db.DateTime, default=datetime.datetime.utcnow)
