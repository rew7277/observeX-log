# ObserveX V7 Enterprise Hardening Fixes

## Fixed in this package

### 1. Thread-safe topology engine
- Removed the fragile runtime monkey-patching between `topology_engine_v3.py` and `topology_engine_v2.py`.
- `topology_engine_v2.extract_architecture_graph()` now accepts a `flow_extractor` callback.
- `topology_engine_v3.py` passes its extractor directly, so parallel uploads cannot corrupt shared function references.

### 2. More accurate severity detection
- Updated `detect_level()` so random numbers such as `200 records fetched` are not treated as HTTP success.
- Error/failure signals now take priority over success wording.
- HTTP 2xx/4xx/5xx codes are only used when found in HTTP/status/response-code context.

### 3. Reduced N+1 DB queries in System Map
- `/api/v1/system-map` now bulk-loads API endpoints for registry entries instead of querying `ApiEndpoint` once per API.
- This improves System Map response time when registry contains many APIs.

### 4. Indexed observability path preserved
- Existing `persist_observability_indexes()` continues writing `LogEvent`, `TraceIndex`, and `FlowEdge`.
- Enterprise APIs can now continue moving away from large `log_rows_json` reads.

## Suggested next V8 improvements

1. Make `/analyse` fully async by default for large/multiple files and return `job_id` immediately.
2. Add a background worker service instead of Python daemon threads for Railway production reliability.
3. Rewrite Trace Explorer to query `TraceIndex` and `LogEvent` directly with pagination.
4. Add DB-level incident auto-creation from alert rules.
5. Add upload chunking in frontend for 20–30 files, with progress per file and retry.
6. Add retention cleanup jobs for `LogEvent`, `TraceIndex`, `FlowEdge`, and raw uploads by plan.
7. Add load-test script for 30 parallel uploads before every production release.
