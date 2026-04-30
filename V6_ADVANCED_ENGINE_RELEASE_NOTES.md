# ObserveX V6 Advanced Engine

## Main upgrades

1. **Fast large-file ingestion path**
   - Files >= 5 MB now use `/analyse/async` from the dashboard.
   - UI polls the ingestion job and reloads the completed session from Postgres.
   - This avoids keeping the browser blocked while the backend parses large Mule logs.

2. **Endpoint-separated topology**
   - System Map grouping now uses Mule route extraction first.
   - `GET /paymentEngine/loanDetails` and `POST /paymentEngine/payment` are stored as separate flow maps.
   - This prevents loan lookup and payment traces from merging into one noisy topology.

3. **Topology Engine V3**
   - Added `topology_engine_v3.py`.
   - Detects BBPS, Setu, UPI Gateway and LMS/Flexcube from Mule payloads.
   - Adds endpoint-aware pruning so payment nodes do not appear inside loan-details flow.

4. **Expected flow output for the uploaded payment-engine sample**
   - Loan Details:
     `s-paymentengine-api → GET /paymentEngine/loanDetails → Loan Details → LMS / Flexcube → Response`
   - Payment:
     `s-paymentengine-api → POST /paymentEngine/payment → Payment Processing → BBPS → Setu → UPI Gateway → Response`

## Deployment notes

- Deploy to Railway as before.
- Keep `DATABASE_URL`, `DATABASE_PUBLIC_URL`, and `JWT_SECRET` configured.
- After deployment, upload the same 10 MB log file and check System Map by endpoint.
- For already-uploaded old sessions, re-upload once so V6 can rebuild endpoint-separated maps.
