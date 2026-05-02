# V46.4 Upload Processing Fix

Fixes the issue where uploads show as accepted but logs never appear in the dashboard.

## Root cause
Railway Redis was present, so the app enqueued ingestion jobs into RQ. But Railway does not automatically run the `worker:` process from `Procfile` unless you create a separate Worker service. Result: jobs stayed queued forever.

## Change
RQ is now opt-in only:

```env
OBSERVEX_ENABLE_RQ=1
```

If this variable is not set, uploads are processed by a web-process background thread so logs appear in the dashboard without requiring a separate worker service.

## Recommended Railway setup
For simple deployment, do **not** set `OBSERVEX_ENABLE_RQ`.

For production queue deployment, create a second Railway service with:

```bash
rq worker observex-ingest
```

Then set this on both web and worker services:

```env
OBSERVEX_ENABLE_RQ=1
REDIS_URL=${{Redis.REDIS_URL}}
OBSERVEX_RQ_QUEUE=observex-ingest
```
