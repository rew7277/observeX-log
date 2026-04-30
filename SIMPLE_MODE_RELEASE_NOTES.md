# ObserveX Simple Mode Update

This build keeps the existing log parser, persistence, topology v4 engine, pagination, trace lookup, and API registry capabilities, but changes the user experience to a simpler operational workflow.

## What changed

- Simplified navigation to: Dashboard, Log Search, System Map, Upload History, Settings.
- Removed heavy enterprise cards from the default dashboard view.
- Added a clear workflow: Upload -> Review -> Search -> Map.
- Simplified System Map rendering to a clean flow path instead of a heavy SVG graph by default.
- Hid noisy deep-dive panels from the main navigation without deleting backend logic.

## User impact

1. Upload logs.
2. See health, errors, RCA, and findings.
3. Search exact log evidence.
4. Open System Map to validate API flow and downstream dependencies.
5. Reopen persisted uploads from Upload History.

## Technical note

The simplification is implemented as `static/simple_mode.js` plus a CSS layer in `templates/dashboard.html`. This is low-risk because it does not remove backend logic or database tables.
