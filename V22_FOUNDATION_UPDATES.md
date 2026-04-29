# ObserveX V22 Foundation Updates

Implemented in this package:

1. Added API inventory foundation tables:
   - `ApiRegistry`
   - `ApiEndpoint`
   - `TraceIndex`
   - `LogEvent`
   - `FlowEdge`

2. Added DB-backed indexing after upload/API ingestion:
   - API Name -> Endpoint -> Flow mapping
   - Environment-aware log events
   - Trace lookup rows
   - Persisted flow edges for System Map

3. Improved Global Search:
   - `/api/v1/logs/search` now searches parsed DB rows first instead of reading raw `.masked.log` files every time.
   - Supports filters like `env:PROD`, `api:customer`, `endpoint:/loan`, `trace:<id>`, `level:ERROR`.

4. Improved Trace Explorer:
   - `/api/v1/trace/<trace_id>` now uses `TraceIndex` first for faster trace lookup.

5. Added API Registry endpoint:
   - `GET /api/v1/api-registry`
   - `POST /api/v1/api-registry`

6. Async ingestion now stores parsed rows, flow map, trace index, and log event index.

7. API ingestion now stores parsed rows, flow map, trace index, and log event index.

Deployment note:
- Existing Railway DBs will create the new tables through `db.create_all()` on startup.
- For production-grade DB management, the next recommended step is moving these schema changes to Flask-Migrate/Alembic migrations.
