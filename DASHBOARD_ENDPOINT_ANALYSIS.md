# Dashboard endpoint analysis and v16 fixes

The dashboard was previously grouping Mule processor fragments like `/processors/0` and `/processors/3`. These are internal Mule processor positions, not business APIs. The uploaded Gupshup log contains true endpoint signatures like `[s-gupshup-api].get:\generate-otp:s-gupshup-api-config`, `[s-gupshup-api].get:\verify-otp:s-gupshup-api-config`, and `[s-gupshup-api].post:\crif\sms:application\json:s-gupshup-api-config`.

Fixes added:
- Backend extracts `api`, `method`, and `flow_group` for each log row.
- Dashboard grouping prioritizes API endpoint over processor path.
- Traffic bars now include dominant API in hover text.
- Added Errors by API / endpoint below the traffic trend.
- Top API cards show endpoint, apps, files, logs, errors, warnings, and traces.
- CSS prevents long endpoint/cards from colliding.

Expected grouping: `/generate-otp`, `/verify-otp`, `/crif/sms`, not `/processors/*`.
