# ObserveX System Map Flow Fix

## Why the previous map was unclear
The uploaded MuleSoft log contains one API listener and one implementation subflow, but the old parser treated message text such as `before loan details log` and `after loan details log` as service nodes. This created fake architecture nodes like `before`, `after`, raw log fragments, or JSON payload fragments.

## Actual flow in the provided log
`Client -> s-paymentengine-api -> paymentengine-loan-details-impl-api-subflow -> Response`

## What changed
- Added MuleSoft listener parsing for `[api].get:\path:config` patterns.
- Added endpoint extraction for backslash Mule paths like `\paymentEngine\loanDetails`.
- Added processor/subflow extraction from `processor: .../processors/N`.
- Removed `before/after ... log` text from architecture node detection.
- Correlated traces/events and calculated latency from first-to-last timestamp when explicit latency is missing.
- Added System Map hints explaining when logs lack external connector/database evidence.
- Updated UI hints/dependency cards to explain why the graph is simple when the uploaded log only contains one service boundary.

## What extra log fields improve architecture mapping
For a full architecture graph, add downstream logs with one of these patterns:
- `before request to cbs-loan-service`
- `after request to cbs-loan-service latency=123`
- `connector=oracle-loan-db operation=select`
- `targetService=customer-service`
- `http.request.host=...` or `db.system=postgresql`

Without those dependency markers, the tool should not invent external systems. It will now show a clean verified flow and explain what evidence is missing.
