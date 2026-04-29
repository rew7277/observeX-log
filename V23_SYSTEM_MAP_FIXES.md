# V23 System Map + Console Error Fixes

Implemented fixes:

- Fixed `renderArchitecture()` null element crash by replacing direct DOM writes with `safeSetHTML()` / `safeSetText()`.
- Corrected System Map hints target from missing `system-map-hints` to existing `flow-hints`.
- Fixed Custom Dashboards, Incidents and Log Metrics sections to use existing container IDs.
- Fixed Source Health, Onboarding and Performance loaders to render into existing page containers instead of missing table/body IDs.
- Added API Registry downstream systems storage using `downstream_systems_json`.
- Added runtime DB compatibility migration for `api_registry.downstream_systems_json`.
- Enhanced `/api/v1/api-registry` POST to accept:
  - `api_name`
  - `environment`
  - `base_url`
  - `owner`
  - `status`
  - `endpoints`
  - `downstream_systems` / `dependencies`
- Enhanced `/api/v1/system-map` to merge manually configured API Registry data with uploaded log-derived flow data.
- System Map now works even if the API exists in registry but detailed trace data is not yet uploaded.

Recommended API Registry payload:

```json
{
  "api_name": "s-paymentengine-api",
  "environment": "PROD",
  "base_url": "https://example.com/paymentengine",
  "owner": "Payments Team",
  "status": "active",
  "downstream_systems": ["BBPS", "RazorPay_Web", "Flexcube"],
  "endpoints": [
    {"method": "GET", "endpoint": "/"},
    {"method": "POST", "endpoint": "/enach/status"}
  ]
}
```
