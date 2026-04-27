# ObserveX – Log Intelligence SaaS

Production-ready Flask app with authentication, log analysis, API ingestion, trace explorer, flow analytics and alert rules. Deployable to Railway.app in minutes.

---

## Features

| Feature | Description |
|---|---|
| **Auth** | Register · Login · Forgot / Reset password (email link) |
| **Drag & Drop** | Upload `.log` `.txt` `.json` files, auto-analysed instantly |
| **Paste Logs** | Paste raw log text directly in the browser |
| **API Ingestion** | `POST /api/v1/logs/ingest` with Bearer API key |
| **S3 Connectors** | UI to configure AWS S3 bucket sync (extend with boto3) |
| **Trace Explorer** | Search by `traceId` / `eventId` across all uploaded logs |
| **Flow Analytics** | Detect `application=xxx` tags and draw service flow |
| **Alert Rules** | Create threshold rules (error %, latency, warn count) |
| **Session History** | View past 50 analysis sessions with all metrics |
| **API Key** | Per-user API key with rotate support |
| **Multi-env** | PROD / UAT / DEV / DR environment selector |

---

## Quick Start (local)

```bash
git clone <your-repo>
cd observex
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python app.py
# open http://localhost:5000
```

---

## Deploy to Railway.app

### 1 – Push to GitHub
```bash
git init && git add . && git commit -m "init"
git remote add origin https://github.com/YOUR_USER/observex.git
git push -u origin main
```

### 2 – Create Railway project
1. Go to [railway.app](https://railway.app) → **New Project** → **Deploy from GitHub**
2. Select your repo → Railway auto-detects Python via nixpacks

### 3 – Add PostgreSQL
In Railway dashboard: **+ New** → **Database** → **PostgreSQL**
Railway sets `DATABASE_URL` automatically.

### 4 – Set environment variables
In Railway → your service → **Variables**:

| Variable | Value |
|---|---|
| `SECRET_KEY` | `openssl rand -hex 32` output |
| `DATABASE_URL` | auto-set by Railway Postgres addon |
| `MAIL_SERVER` | `smtp.gmail.com` (or your SMTP) |
| `MAIL_PORT` | `587` |
| `MAIL_USERNAME` | your Gmail address |
| `MAIL_PASSWORD` | Gmail App Password |

> **Gmail App Password**: Google Account → Security → 2-Step Verification → App Passwords → create one for "Mail"

### 5 – Deploy
Railway deploys automatically on every push. Domain is auto-assigned under `*.up.railway.app`.

---

## API Reference

### Ingest logs
```
POST /api/v1/logs/ingest
Authorization: Bearer <api_key>
Content-Type: application/json

{
  "environment": "PROD",
  "application": "payment-engine",
  "logs": "<raw log content>"
}
```

**Response**:
```json
{
  "status": "ok",
  "session_id": 42,
  "total": 1200,
  "errors": 3,
  "warns": 12,
  "latency": 245,
  "apps": ["payment-engine", "auth-service"],
  "traces": ["abc-123"],
  "events": ["evt-999"],
  "findings": [...],
  "flow": "payment-engine → auth-service"
}
```

---

## Log format tips

For best detection, include these fields in your logs:
```
application=payment-engine traceId=abc-123 eventId=evt-999 latency=342 ERROR timeout
```

---

## Project structure

```
observex/
├── app.py               # Flask app – routes, models, analysis engine
├── requirements.txt
├── Procfile             # gunicorn start command
├── railway.json         # Railway deploy config
├── nixpacks.toml        # Build config
└── templates/
    ├── base.html        # Shared layout, CSS design system
    ├── login.html
    ├── register.html
    ├── forgot_password.html
    ├── reset_password.html
    └── dashboard.html   # Full SPA-style dashboard
```
