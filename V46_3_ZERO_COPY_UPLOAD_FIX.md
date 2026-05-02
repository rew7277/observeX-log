# V46.3 Zero-Copy Upload Fix

## Problem
50 MB uploads could still take 15-20 minutes because `/analyse` read the uploaded file into memory, decoded the full text, and only then queued the job. That kept the HTTP request on the slow path.

## Fix
- `/analyse` now detects large multipart uploads before reading them.
- Large files are saved directly from Werkzeug's upload stream to `observex_uploads/_incoming/<user>/...`.
- The request immediately creates an `IngestionJob` and returns `202`.
- The worker processes the file path using streaming counters and bounded head/tail sampling.
- `/analyse/async` also uses the disk-path queue instead of reading the whole file into memory.

## Recommended Railway variables
```env
OBSERVEX_ASYNC_UPLOAD_BYTES=262144
OBSERVEX_FAST_HEAD_BYTES=524288
OBSERVEX_FAST_TAIL_BYTES=524288
OBSERVEX_COUNT_CHUNK_BYTES=1048576
OBSERVEX_STORE_LARGE_RAW=0
OBSERVEX_KEEP_INCOMING_UPLOADS=0
```

## Important
The browser still has to physically upload the file to Railway. Server-side processing should return quickly after upload completion, but actual network upload speed depends on user bandwidth and Railway ingress.
