# ObserveX V24 Reliability + System Map Updates

## Fixed
- Reliability tab pages now have matching DOM containers and safe JS loaders:
  - Onboarding
  - Source Health
  - Performance
  - Custom Dashboards
  - Incidents
  - Log Metrics
- Added defensive `setHTML` / `setText` helpers to prevent `Cannot set properties of null` crashes.
- System Map rendering now uses guarded DOM writes for topology, overview, endpoint list and trace waterfall.

## Added
- API Registry / Manual Flow Builder UI inside System Map.
- Manual API mapping fields:
  - API name
  - Environment
  - Base URL
  - Owner/team
  - Endpoint list
  - Downstream systems
- Flow Confidence indicator.
- Error Ownership card.
- Endpoint SLA card.
- Trace Comparison card.
- Smart RCA recommendations.
- Upload Quality Check under Onboarding.
- Retention guidance under Log Metrics.

## Notes
- Manual API Registry data is saved through `/api/v1/api-registry` and merged with uploaded log-derived System Map data.
- Upload logs with trace/correlation IDs to improve Flow Confidence from Medium to High.
