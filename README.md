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

## v4 Intelligent Debugging Update

This package has been updated to make ObserveX simpler, more unique and more productive:

- Replaced tool-first landing page with a **What’s wrong right now?** dashboard.
- Added natural-language style search input for questions like `OTP failures today`, `slow Salesforce traces`, and `JWT errors`.
- Added automatic **root-cause hypothesis** generation from repeated errors, hot traces, dependencies and latency.
- Added **guided debugging** cards: failing trace, top impacted app, dependency signal and deployment readiness.
- Added application health scoring and an error timeline in the System Map.
- Added trace explanation so users can understand why a trace matters before reading raw logs.
- Changed Deployment Validation into **Change Impact**, focused on release decisions instead of manual table comparison.
- Kept existing API ingestion, alert rules, session history, CSV export and auth flow.

The backend changes are in `analyse_log_text()` inside `app.py`. The updated product UX is in `templates/dashboard.html`.

## v5 SaaS/security update

### Railway volume memory
Mount a Railway volume at `/data` and set:

```bash
OBSERVEX_DATA_DIR=/data
MAX_UPLOAD_MB=500
```

ObserveX stores a masked copy of each uploaded/API-ingested log under `/data/observex_uploads/<user-id>/`. Deleting an upload from Upload History removes the saved summary and the masked persisted log file.

### PII and secret masking
Before logs are displayed, exported, stored in the Railway volume, or returned by API responses, ObserveX masks:

- JWT and bearer tokens
- API keys, access tokens, refresh tokens, passwords, secrets, signatures and HMAC values
- Aadhaar numbers
- PAN card numbers
- Indian mobile numbers
- Email addresses
- Customer names
- Customer IDs, loan IDs, loan numbers, account numbers, application numbers
- Payment IDs, BBPS IDs, UPI/VPA, receipt IDs and transaction IDs

For enterprise SaaS, keep masked storage as the default and add encrypted raw retention only as an admin-controlled option.


## ObserveX v6 SaaS-ready additions

### Storage on Railway Basic
Current default:
- Railway Volume mounted at `/data`
- SQLite metadata database
- Masked raw logs stored under `OBSERVEX_DATA_DIR=/data`

Recommended Railway variables:
```bash
OBSERVEX_DATA_DIR=/data
MAX_UPLOAD_MB=500
DEFAULT_RETENTION_DAYS=30
```

### Can we use MongoDB?
Yes. For Railway Basic, do **not** run MongoDB inside the same small Railway service. Prefer **MongoDB Atlas free/shared tier** and connect using:
```bash
MONGO_URI=mongodb+srv://<user>:<password>@<cluster>/<db>?retryWrites=true&w=majority
MONGO_DB_NAME=observex
```

Current MongoDB usage is optional and safe:
- Mirrors audit events when configured
- Future-ready for investigation documents, connector configs, saved RCA reports, and lightweight searchable metadata

For very large enterprise log search, later add:
- Object storage/S3 for raw logs
- Postgres for tenant/user/billing metadata
- ClickHouse or OpenSearch for fast indexed log search

### New SaaS features added
- Workspace model with role foundation: Admin, Developer, Viewer, Auditor
- Tenant/user scoped data isolation
- Retention policy with cleanup endpoint
- Audit trail for uploads, deletes, exports, connector changes, settings changes, API search, and trace lookup
- Alert destinations: email, Slack, Teams, webhook
- Source connectors: S3, CloudWatch, MuleSoft, Kafka, webhook
- Usage/cost visibility: stored file count, volume MB, sessions, max upload size
- Compliance screen
- Optional MongoDB audit mirror
- API search endpoint: `GET /api/v1/logs/search`
- API trace endpoint: `GET /api/v1/trace/<trace_id>`

### Security
ObserveX masks JWTs, bearer tokens, API keys, Aadhaar, PAN, mobile numbers, emails, customer names, loan/account/customer/payment IDs, UPI/VPA, BBPS/payment identifiers and other common secrets before UI display, CSV export, volume storage, and API response.

## v7 SaaS/Product Reliability Upgrade

Added on top of v6:

- Public website pages: `/`, `/features`, `/product`, `/security`, `/pricing`
- Separate authenticated app endpoints: `/dashboard`, `/log-search`, `/system-map`, `/change-impact`, `/api-ingestion`, `/alerts-page`, `/connectors-page`, `/compliance-page`, `/upload-history`, `/settings-page`
- Demo mode: `/demo/load`
- Onboarding wizard: `/onboarding/status`
- Plan/limits API: `/limits`
- Data source health: `/data-source-health`
- Queue-style async ingestion: `POST /api/v1/logs/ingest-async` and `/ingestion/jobs`
- Query/upload performance metrics: `/performance`
- Incident severity score and schema detection returned in every analysis response
- Explainable RCA evidence: top errors, hot traces, dependency signals and timeline buckets
- Customer-safe masked report sharing: `POST /reports/share` and public `/r/<token>`
- Workspace invite codes and role-based access helpers: `/workspace/invites`, `/workspace/members`
- Settings now shows current plan, role, workspace and plan limits
- Login/register branding updated to ObserveX `OX`

### Railway Basic storage recommendation

Keep the current Railway Volume setup for the MVP:

```bash
OBSERVEX_DATA_DIR=/data
MAX_UPLOAD_MB=500
```

For metadata/audit/report storage without Postgres, use MongoDB Atlas:

```bash
MONGO_URI=mongodb+srv://...
MONGO_DB_NAME=observex
```

MongoDB is optional. If `MONGO_URI` is missing, the app still works using SQLite + Railway Volume. For larger enterprise search, later add ClickHouse or OpenSearch.
