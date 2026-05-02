# V46.2 Fast Ingestion Updates

## Why 50 MB previously took too long
The older pipeline accepted the file quickly, but the worker still performed expensive operations over very large raw text:

- regex-heavy log parsing over a large payload,
- topology extraction over the full raw file,
- masking and writing the full raw file to disk,
- inserting thousands of per-row observability records in one job.

For 50 MB logs this can push processing into many minutes on a small Railway CPU.

## What changed

### Fast large-file mode
Large files now use a bounded head/tail sample for detailed intelligence while full-file totals are counted with cheap scans.

Environment variables:

```env
OBSERVEX_LARGE_FILE_BYTES=8388608
OBSERVEX_FAST_HEAD_BYTES=2097152
OBSERVEX_FAST_TAIL_BYTES=1048576
OBSERVEX_STORE_LARGE_RAW=0
```

Default behavior:

- Files below 8 MB are analyzed normally.
- Files at or above 8 MB analyze 2 MB from the head and 1 MB from the tail.
- Full total/error/warn counters are calculated from the complete file.
- Topology, RCA, trace samples, and UI rows are built from the bounded sample.
- Large raw file persistence is skipped by default to avoid slow masking/write passes.

### Expected speed
On a small Railway instance, this targets seconds-level completion for 50 MB instead of minutes, depending on CPU, Redis, and database speed.

## Important tradeoff
This is optimized for dashboard speed. For forensic full-file search across every row, connect object storage plus a streaming parser/indexer. Do not parse 50 MB synchronously inside Flask/Gunicorn.
