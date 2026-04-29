# V36 System Map + Trace Fallback Fixes

- Fixed topology generation so processor/event IDs are not treated as APIs or topology nodes.
- Rebuilt topology from Mule processor order instead of generic tag order.
- Hidden noisy nodes: common, default, Logging, Mule-Subflow, External-Service placeholder.
- Added derived waterfall and call matrix fallback when logs do not contain distributed trace spans.
- Added response-time/error propagation into derived matrix.
- Cleaned old stored architecture payloads at API response time, so previously uploaded data also renders cleaner.
- Improved API Registry/System Map filtering for processor-* rows.
