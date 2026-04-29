# V25 Log Search + Upload History Fixes

Implemented fixes:

- Fixed Upload History delete/clear 500 by deleting child index tables before deleting `LogSession`:
  - `LogEvent`
  - `TraceIndex`
  - `FlowEdge`
  - `ApiFlowMap`
- Added rollback + JSON error response for safer Railway debugging.
- Added missing `applyClientSearch()` function used by the Log Search Search button.
- Added working handlers for:
  - Search
  - Clear
  - Level chips: Info / Debug / Error / Success / Failure
  - Has trace chip
  - Query language examples like `env=SANDBOX app=demo-checkout-api level=ERROR` and `trace=...`
- Improved Trace Explorer button handling.
- Added safer client-side `safeJson()` to avoid UI crashes when server returns empty/non-JSON error responses.
- Added filter refresh for File/App dropdowns after uploads or session reloads.

Deployment note:

After deploying this ZIP to Railway, restart the service and hard-refresh the browser once to clear cached dashboard JavaScript.
