# V46.5 Reliable Upload + Ingestion Fix

## Problem fixed
Uploads could stay forever in `uploading` / `indexing` because large files were queued to Redis/RQ or daemon threads, but Railway did not have a separate worker running the queue. Result: the browser said upload accepted, but no `LogSession` rows were written, so the dashboard stayed empty.

## What changed
- `/analyse` now ingests uploaded files synchronously by default.
- `/analyse/async` is kept for compatibility, but also performs completed inline ingestion.
- Large files are still fast because the backend reads only a bounded head/tail sample for intelligence and uses streaming counters for full-file totals.
- The dashboard upload JavaScript now posts to `/analyse` and expects completed data, not a stuck queue.
- A final override in `static/topology_upgrade.js` prevents older async upload logic from taking over.
- Redis/RQ can remain installed, but upload ingestion no longer depends on a worker.

## Recommended Railway variables
```
OBSERVEX_ENABLE_RQ=0
OBSERVEX_FAST_HEAD_BYTES=2097152
OBSERVEX_FAST_TAIL_BYTES=1048576
OBSERVEX_COUNT_CHUNK_BYTES=1048576
OBSERVEX_STORE_LARGE_RAW=0
OBSERVEX_SYNC_TOPOLOGY=0
```

Set `OBSERVEX_SYNC_TOPOLOGY=1` only after uploads are stable and you want topology generated during the upload request.
