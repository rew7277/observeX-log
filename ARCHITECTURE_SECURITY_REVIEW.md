# ObserveX Architecture & Security Review (v14)

## Scalability loopholes fixed or prepared
- Public/docs examples now use dummy data only; no real app names, trace IDs, or API tokens in marketing/docs.
- API ingestion supports request-size guardrails with `MAX_INGEST_BYTES` and returns `413` for oversized payloads.
- Lightweight API rate limiting returns `429` to protect Railway Basic deployments.
- Storage remains abstracted for Railway Volume now, MongoDB Atlas next, Postgres/ClickHouse/OpenSearch later.
- Dashboard is driven from ingested sessions and active rows instead of static hardcoded app/dependency names.

## Remaining production architecture recommendations
1. Move 500MB+ uploads to pre-signed object storage and process them in a background worker.
2. Keep raw masked logs in object storage, metadata in MongoDB/Postgres, and searchable events in ClickHouse/OpenSearch.
3. Use a durable queue for ingestion jobs and retries. Railway Basic can start with a file-backed queue, but Redis/BullMQ/Celery is better.
4. Add tenant-scoped indexes for workspace ID, environment, application, timestamp, level, event ID, and file ID.
5. Add async delete jobs so removing an uploaded file deletes related rows, traces, metrics, incidents, and reports.

## Website security checklist
- Security headers added: CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.
- Keep session cookies secure in production.
- Add CSRF tokens for form POSTs before public launch.
- Add audit logs for login, invite, role, export, delete, and API key rotation.

## API security checklist
- Never expose real API keys on public pages.
- Use HTTPS only.
- Hash API keys at rest before production.
- Add per-workspace API quotas, per-key rotation, and last-used timestamps.
- Validate content type and reject unsupported payloads.
- Mask secrets before persistence and before any export/report sharing.
- Add HMAC signatures for high-trust integrations later.

## v18 hardening update
- Removed dead tmp.js/tmp2.js and committed __pycache__ artifacts.
- Dockerfile is the selected Railway deployment path; Procfile/nixpacks removed to avoid conflicting build strategies.
- SECRET_KEY now warns loudly when missing so Railway sessions are not unexpectedly invalidated after restart.
- Alert execution engine added: alert rules are evaluated after file/API ingestion, firings are stored, and email destinations are notified in MVP mode.
- Added operational endpoints/dashboards: /api-keys, /alert-firings, /retention/status, /activity/summary.
- Retention cleanup now has preview/status and destructive apply endpoint.
- API ingestion keeps rate limit, payload limit, API key auth, PII masking, audit events, and alert evaluation.
