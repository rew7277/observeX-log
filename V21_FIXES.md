# ObserveX v21 Fixes

This release fixes the duplicated frontend patches and adds the requested dashboard/system-map/masking improvements.

## Fixed
- Removed duplicate v19 dashboard filter block and duplicate log pagination block.
- Kept a single v20/v21 traffic trend filter set.
- Kept a single pagination control for Log Search.
- Increased table, card, filter, chart and log-detail font sizes for readability.

## System Map v21
- Groups logs by detected application.
- Shows API/endpoint counts under each application.
- Clicking an application renders its endpoint list.
- Clicking an endpoint opens matching logs in Log Search.
- Flow path is built from the active dataset: Client -> App -> Endpoint(s).
- Dependency chips are detected from log content keywords.

## Premium Custom Masking
- Settings includes Premium Custom Masking Rules.
- Customers can add extra keys like cardToken, employeeId, memberId, customerDOB, internalSecret.
- Displayed log rows and complete log modal apply these masking rules.
- Current storage is local browser storage. Backend persistence can be added for Enterprise plans later.
