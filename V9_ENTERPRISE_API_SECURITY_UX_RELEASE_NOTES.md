# ObserveX V9 Enterprise API + Security + UX Release Notes

## Added in V9

### Frontend / UX
- Added persistent dark/light theme toggle using browser localStorage.
- Added shared CSS helpers for upload progress bars and incident timelines.
- Kept existing dashboard functionality intact.

### Backend
- Added login brute-force protection using the existing Redis/in-memory rate limiter.
- Added incident detail API with evidence expansion from TraceIndex/LogEvent.
- Added JSON log export endpoint with API-key authentication and export rate limiting.
- Added best-effort alert notification fan-out for Email, Slack, Teams, and generic webhooks.
- Alert evaluation now attempts notification delivery when an incident is created.

### API Level
- Added OpenAPI JSON endpoint: `/api/v1/openapi.json`.
- Added lightweight API docs page: `/api/swagger`.
- Added test-alert endpoint: `POST /api/v1/alerts/test`.
- Added incident detail endpoint: `GET/PATCH /api/v1/incidents/<incident_id>`.
- Added export endpoint: `GET /api/v1/logs/export`.

## Deployment notes
- Existing V8 routes remain compatible.
- For Slack/Teams/webhook alerts, configure alert destinations from the existing alert destination API/UI.
- For email alerts, set SMTP variables in Railway: `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USERNAME`, `MAIL_PASSWORD`.
- For stronger rate limiting in production, set `REDIS_URL`.

## Suggested V10 roadmap
- Move background jobs from in-process threads to Redis Queue/Celery workers.
- Add Alembic/Flask-Migrate instead of runtime `ALTER TABLE` compatibility patches.
- Add ClickHouse/OpenSearch when log volume crosses millions of events per day.
- Add Jira/GitHub deployment correlation to incidents.
