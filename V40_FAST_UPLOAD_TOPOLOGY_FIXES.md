# V40 Fast Upload + Real Topology Fixes

## Upload performance
- Server now returns a lightweight analysis payload: first 1000 preview rows only, messages truncated for UI.
- Server still indexes up to 5000 rows for System Map/Trace/Registry.
- Raw uploaded file persistence now runs asynchronously, so the HTTP request is not blocked by disk writes.
- Frontend uploads multiple files concurrently with a 3-worker queue instead of one-by-one serial upload.

## Topology engine
- Topology is now generated from event-grouped Mule traces.
- Uses ENTRY / CALL-ENTRY / processor / CALL-EXIT / EXIT semantics.
- Prevents reversed Response → API maps.
- Forces sane direction: API → endpoint/business stage → processor/subflow → downstream → Response.
- Detects business stages for LMS loan receipt, payment engine loan details, Gupshup OTP, HTML-to-PDF, Kotak eMandate.
- Detects downstream systems such as Gupshup, Salesforce, LMS Core, Kotak NACH, HTML/PDF Engine.

## API Registry
- Keeps processor/event pseudo APIs filtered from topology output.
- Delete support from previous version is preserved.

After deployment, re-upload/re-analyse logs once so old stored architecture payloads are rebuilt with V40 logic.
