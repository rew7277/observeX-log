# V39 Full System Map + Registry Fixes

## What changed

- Added API Registry delete support on `/api/v1/api-registry`.
- Added Delete button in grouped API Registry UI.
- Delete removes registry row, endpoint inventory, saved API flow maps, and flow-edge cache for that API/environment without deleting uploaded log files.
- Improved Mule route parsing for real log patterns like `get:\paymentEngine\loanDetails`, `post:\loan\receipt`, and `post:/htmltopdfv2:text\html`.
- Manual registry fallback now builds a real flow: `Client -> METHOD endpoint -> API -> downstream systems -> Response`.
- Registry fallback now also generates synthetic Trace Waterfall and Call Matrix, so the UI no longer shows empty waterfall/matrix when manual endpoint data exists.
- Topology clean-flow UI now preserves Client and External/System nodes instead of filtering them away.

## After deploy

Re-upload or re-analyse logs once so old cached system-map rows are rebuilt with the new parser.
