# ObserveX v46 Enterprise Architecture, Dashboard & Security Updates

## Included changes

### 1. Durable ingestion queue support
- Added optional Redis/RQ durable queue for `/analyse` and `/analyse/async` background ingestion.
- If `REDIS_URL` is configured, uploads are enqueued to `observex-ingest` instead of relying only on Gunicorn daemon threads.
- If Redis/RQ is unavailable, the app safely falls back to the previous in-process thread behavior for local development.
- Added `worker.py` and `worker: rq worker observex-ingest` Procfile entry.

### 2. PostgreSQL row-size protection
- Reduced `LogSession.log_rows_json` from thousands of rows to a small preview cache.
- Full searchable/reloadable rows are served from the normalized `LogEvent` table where available.
- `/api/v1/sessions/<id>/rows` now loads `LogEvent` rows first, then falls back to `log_rows_json` only for older sessions.

### 3. Connector secret protection
- Added connector config encryption helpers using `CONNECTOR_SECRET_KEY` / `FERNET_KEY` when configured.
- If encryption is not configured, secret-looking fields are redacted before persistence.
- Connector list responses redact secret-looking fields before returning to the UI.

### 4. Dashboard visualization upgrade
- Added Chart.js support for the traffic/errors/warnings trend panel with tooltips, axes and legend.
- Kept CSS-bar fallback when Chart.js is unavailable.
- Donut chart now calculates healthy/warning/failure mix from real active dataset counts instead of fixed values.
- Added KPI count-up animation and staggered bar-entry animations.

### 5. CSP hardening path
- Added `OBSERVEX_STRICT_CSP=1` mode to remove script `unsafe-inline` after the remaining inline dashboard script is moved fully to static JS.
- Added `cdn.jsdelivr.net` to script CSP for Chart.js.

## Production notes

For durable queue mode on Railway or similar platforms:

```bash
REDIS_URL=redis://...
CONNECTOR_SECRET_KEY=<fernet-key>
rq worker observex-ingest
```

Generate a Fernet key:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Recommended next refactor: move the remaining inline `templates/dashboard.html` JavaScript into `static/dashboard.js`, then enable `OBSERVEX_STRICT_CSP=1`.
