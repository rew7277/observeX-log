# ObserveX V31 Enterprise UX Updates

This build converts the V30 enterprise foundations into a more usable decision-making dashboard.

## Added / improved
- Actionable RCA panel with confidence, owner, cluster count, top evidence, collapsed raw evidence, and guided action buttons.
- Endpoint SLA panel with score plus latency, error, and availability breakdown bars.
- Executive report preview cards showing incident count, SLA score, top issue, and owner before download.
- Findings summary strip that replaces raw log walls with concise errors, warnings, top issue, and affected API summaries.
- Grouped Smart Tags into Flows, APIs, Errors, Infra, and Other to reduce visual noise.
- Clickable drilldowns from KPI cards, findings, top error clusters, guided debugging, and action cards.
- Existing global search, live alerts, trace compare, report download, and light theme remain included.
- Extra CSS for readable enterprise panels and responsive layouts.

## Notes
- These are pragmatic product foundations using the current parsed logs and indexed events.
- RCA remains rule/correlation-based, not a hosted LLM or ML model.
- Live alerts are polling-based from current ingested data, not yet WebSocket streaming.
