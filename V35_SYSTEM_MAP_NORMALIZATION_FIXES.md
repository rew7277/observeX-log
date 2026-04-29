# V35 System Map Normalization Fixes

## Fixed
- Prevented Mule processor/event IDs from being treated as API Registry entries.
- Normalized noisy Mule names such as `processor-make-api-call-event-...` into stable logical components like `make-api-call`.
- Recovered real API names from Mule runtime/config log patterns when a log line is processor-heavy.
- Hidden invalid processor/event rows from API Registry and System Map responses.
- Added clean execution topology rendering: `Client → API → flow/subflow → make-api-call → External-Service → Response`.
- Added `simple_flow` metadata into the architecture payload so the UI renders a clean flow first, instead of a noisy tag chain.
- Blocked manual registry saves for processor event IDs.

## Important
Existing old DB rows with processor event IDs are now hidden from the UI. For best results, re-upload/re-analyse the log file so the cleaned indexes are rebuilt.
