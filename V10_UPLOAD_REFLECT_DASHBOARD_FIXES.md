# ObserveX V10 - Upload Reflection & Dashboard Refresh Fixes

This build fixes the gap where uploads were accepted/queued but did not automatically appear in Dashboard, Trace Explorer, System Map, or Upload History.

## Fixed

- Ingestion jobs now store `session_id` after the background worker creates the `LogSession`.
- `/ingestion-jobs/<job_id>` now returns:
  - `session_id`
  - `progress`
  - `rows_url`
  - `result_url`
- Background worker updates progress during major stages:
  - queued/running
  - parsed
  - session created
  - indexed
  - completed
- Dashboard polling now automatically loads `/api/v1/sessions/<session_id>/rows` after job success.
- Queued upload placeholder is replaced with the real completed session.
- Dashboard, Upload History, System Map, Logs Search, and Trace Explorer refresh after completion.
- Trace Explorer now falls back to indexed DB lookup if the trace is not present in active browser memory.
- Existing Railway databases are upgraded safely using runtime compatibility columns for `ingestion_job.session_id` and `ingestion_job.progress`.

## Why this was needed

V9 correctly introduced background ingestion, but the frontend stopped after polling job success. The completed session existed in the database, but the active dashboard memory (`_allRows`) was not hydrated again. V10 closes that loop.

## Deployment note

After deployment, upload logs and wait until the upload status shows `indexed and loaded into dashboard`. If old queued jobs existed before this build, upload again or reload them from Upload History.
