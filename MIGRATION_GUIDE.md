# ObserveX — Migration Guide

This document explains how to adopt all the refactored files in this update.

---

## Project structure after this update

```
observeX/
├── app.py                  # Slim orchestrator (was 4,575 lines — now ~350 lines of glue)
├── extensions.py           # db, mail — shared instances (NO circular imports)
├── models.py               # All SQLAlchemy models in one place
├── requirements.txt        # Updated with flask-migrate, cryptography, rq, python-magic
│
├── routes/
│   ├── auth.py             # Login, register, Google OAuth, reset password
│   └── logs.py             # /analyse, /analyse/async, /api/v1/logs/ingest, /history, /export/csv
│
├── services/
│   ├── security.py         # API keys, CSRF, Fernet encryption, masking, lockout
│   └── tasks.py            # RQ / Celery / thread task queue for ingestion
│
├── migrations/
│   └── env.py              # Alembic env for Flask-Migrate
│
└── static/
    ├── dashboard.js        # All dashboard JS (external — removes 'unsafe-inline' from CSP)
    └── dashboard.css       # All dashboard CSS (external)
```

---

## Step-by-step deployment on Railway

### 1. Install new dependencies

```bash
pip install -r requirements.txt
# Also needed on the OS (nixpacks): libmagic1
# Add to nixpacks.toml:
# [phases.setup]
# nixPkgs = ["libmagic"]
```

### 2. Set new environment variables on Railway

| Variable | Purpose | Example |
|---|---|---|
| `OBSERVEX_FERNET_KEY` | Encrypts connector secrets at rest | Generate with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `OBSERVEX_WEBHOOK_SECRET` | HMAC signature on outbound webhooks | Any random string |
| `REDIS_URL` | Task queue + rate limiter | Railway Redis plugin |
| `LOGIN_LOCKOUT_MAX_FAILURES` | Failures before account lock (default 10) | `10` |
| `LOGIN_LOCKOUT_MINUTES` | Lock duration (default 15) | `15` |

### 3. Migrate the database with Flask-Migrate (replaces `db.create_all`)

```bash
# First time only — creates the migrations/ folder if it doesn't exist
export FLASK_APP=app.py
flask db init

# Detect model changes and generate a migration script
flask db migrate -m "modularisation refactor v46"

# Review the generated script in migrations/versions/*.py, then apply
flask db upgrade
```

**After this, never run `db.create_all()` or raw `ALTER TABLE` for schema changes.**
Always use `flask db migrate` + `flask db upgrade`.

### 4. Rotate reset tokens

The reset-token column is now hashed at rest (`reset_token_hash`).
Old plaintext tokens in `reset_token` are still accepted for backward compat,
but expire as users request new resets.

### 5. Provision Redis for the task queue

Add Railway's Redis plugin.
`tasks.py` auto-detects `REDIS_URL` and switches from thread → RQ automatically.
No code change needed.

To start the RQ worker on Railway, add a second service with start command:

```bash
rq worker observex-ingestion --url $REDIS_URL
```

### 6. Move dashboard.html inline JS/CSS to external files

Replace the inline `<style>` block in `dashboard.html` with:
```html
<link rel="stylesheet" href="{{ url_for('static', filename='dashboard.css') }}">
```

Replace the inline `<script>` block with:
```html
<script src="{{ url_for('static', filename='dashboard.js') }}"></script>
<!-- Chart.js from CDN (already allowed in CSP) -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
```

Add the new donut SVG to the health card in dashboard.html:
```html
<svg class="donut-svg" viewBox="0 0 100 100">
  <circle class="donut-track"  cx="50" cy="50" r="44"/>
  <circle class="donut-good"  id="donut-good"  cx="50" cy="50" r="44"/>
  <circle class="donut-warn"  id="donut-warn"  cx="50" cy="50" r="44"/>
  <circle class="donut-error" id="donut-error" cx="50" cy="50" r="44"/>
</svg>
<span id="donut-label">–</span>
```

Add the trend chart canvas (replaces the CSS flex bars):
```html
<div class="trend-card">
  <div class="trend-card-title">Log volume over time</div>
  <div class="trend-canvas-wrap">
    <canvas id="dash-trend-canvas"></canvas>
  </div>
</div>
```

### 7. KPI tiles — add IDs for countUp

Ensure each KPI tile value element has the matching ID:
```html
<div class="kpi-tile error">
  <div class="kpi-tile-label">Errors</div>
  <div class="kpi-tile-value" id="kpi-errors">–</div>
</div>
<!-- Similarly: kpi-total, kpi-warns, kpi-latency, kpi-health -->
```

---

## What's NOT changed (kept identical to v45)

- All topology parsing logic (`extract_architecture_graph`, `extract_system_map`, MuleSoft engine).
- All log parsing and schema detection (`analyse_log_text`, `schema_detection_sample`).
- System Map API (`/api/v1/system-map`), API Registry (`/api/v1/api-registry`).
- Trace lookup (`/api/v1/trace/<id>`).
- Masking, audit, retention, workspace, connectors, alert-destinations routes.
- Gunicorn config (`gunicorn_config.py`) — `pool_recycle=280`, `post_fork` SSL disposal.

---

## Deferred (next sprint)

| Item | File to create |
|---|---|
| Extract `analyse_log_text` | `services/log_parser.py` |
| Extract topology engine | `services/topology.py` |
| Extract settings routes | `routes/settings.py` |
| Extract system-map / registry routes | `routes/api.py` |
| Remove `log_rows_json` column | `flask db migrate -m "drop log_rows_json"` after backfill |
| ClickHouse for LogEvent at scale | `services/clickhouse.py` |
