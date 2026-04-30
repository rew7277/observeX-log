# ObserveX V8 Enterprise Hardening

This build adds the next set of production fixes discussed after V7.

## Implemented

1. Background upload worker
- `/analyse` now automatically queues large or multi-file uploads instead of blocking the HTTP request.
- Threshold is configurable with `OBSERVEX_ASYNC_UPLOAD_BYTES`.
- `/analyse/async` now uses the same queue helper.
- `/ingestion-jobs/<id>` returns queued/running/success/failed status for polling.

2. Upload progress per file
- Dashboard upload flow now handles queued responses.
- UI polls ingestion job status and shows per-file queued/running/completed information.

3. DB-first Trace Explorer
- Added logged-in endpoint `/api/v1/trace-ui/<trace_id>`.
- Trace lookup now reads `TraceIndex` first, then `LogEvent`, before falling back to client-side rows.

4. Real incident engine
- New `maybe_create_incident_from_rows()` creates or updates open incidents from repeated errors or latency breach signals.
- Runs after sync ingestion and background ingestion.

5. Alert rule evaluation hook
- Added `/api/v1/enterprise/alerts/evaluate` for manual/automation-triggered evaluation.

6. Retention apply endpoint
- Added `/retention/apply` to apply the configured retention policy immediately.

7. Tenant/environment isolation improvements
- Enterprise RCA/SLA/live alerts/report/global search now use DB-first filtering and environment-aware row loading.
- API registry owner lookup in RCA supports user filtering.

8. API key integration remains active
- Existing `/api/v1/logs/ingest` API-key ingestion is preserved.

## Recommended V9

- Replace in-process threads with a real worker queue: Redis Queue, Celery, Dramatiq, or Railway worker service.
- Add Alembic/Flask-Migrate for safe DB schema upgrades instead of `create_all` compatibility patches.
- Add OpenSearch/ClickHouse when event volume grows beyond Postgres-friendly search.
- Add Slack/Teams/Jira outbound notification delivery for auto incidents.
- Add per-tenant workspace IDs to all observability tables for stronger multi-workspace isolation.
