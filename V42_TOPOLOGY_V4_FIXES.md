# V42 Topology v4 Fixes

## Fixed
- Backend now imports `topology_engine_v4.py` instead of v3.
- Added generic Mule/API topology reconstruction for subflows, flow-ref names, HTTP downstream URLs, CBS/Core Banking, LMS, Credit Bureau, KYC Provider, BBPS, Setu and UPI Gateway.
- Strengthened processor noise filtering so raw paths like `s-paymentengine-api/processors/0` are not shown as architecture nodes.
- Dashboard inline renderer no longer short-circuits to simple pill cards when a clean flow has 3+ steps. This allows the full tiered SVG topology renderer to run.
- `static/topology_upgrade.js` now synthesizes topology directly from active `_allRows` when backend topology is sparse, so uploaded logs can still produce a richer architecture view.

## Expected result
System Map should show a tiered architecture topology with logical services/dependencies instead of raw processor events, and should work better for generic MuleSoft/API logs beyond the previously hardcoded payment examples.
