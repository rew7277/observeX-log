# V38 API Registry + Mule Flow Teaching

Updates:
- Added DELETE support for API Registry entries.
- Added Delete button in API Registry UI.
- Taught parser to read Mule runtime route signatures:
  - `[app].post:\loan\receipt:...` -> `POST /loan/receipt`
  - `[app].get:\paymentEngine\loanDetails:...` -> `GET /paymentEngine/loanDetails`
  - `[app].get:\generate-otp:...` -> `GET /generate-otp`
  - `[app].get:\verify-otp:...` -> `GET /verify-otp`
  - `[app].post:\htmltopdfv2:text\html:...` -> `POST /htmltopdfv2`
- Groups processor IDs into business stages instead of creating fake API rows.
- System Map topology now uses business stages: Request Entry, Token/Auth, Loan Receipt, Loan Details, Generate OTP, Verify OTP, HTML to PDF, downstream system, Response.
- Trace waterfall now uses actual Mule processor/event sequence when trace IDs exist.
- Endpoints are no longer collapsed to only `/` when Mule route metadata exists.

Important:
After deploy, re-upload/re-analyse the log files so old stored registry and flow map data is rebuilt with the improved parser.
