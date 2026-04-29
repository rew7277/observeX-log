# V37 System Map Lane Fixes

- Rebuilt System Map flow normalization to remove generic framework tags such as `External-Service`, `Logging`, `common`, `Mule API`, `JWT Validation`, and `API Router` from the primary topology lane.
- Processor event IDs are ignored and grouped under meaningful Mule components.
- Topology now prefers real business/API steps such as application name, subflow name, `make-api-call`, downstream system, and response.
- Added derived external system placement after outbound calls when no downstream system name is available.
- Preserved trace waterfall and call matrix fallbacks from V36.

After deploying this version, re-upload/re-analyse logs once so existing stored topology records are rebuilt with the cleaner sequence.
