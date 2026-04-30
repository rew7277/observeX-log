# V42 Registry ↔ Topology Bridge

## Added
- API Registry now supports a curated **Flow Builder** field.
- Manual flow steps are stored in `api_registry.flow_steps_json`.
- Registry flow is used by System Map when auto-detection is incomplete or noisy.
- Added **Push detected flow to API Registry** action from System Map.
- Added **Use Selected Topology** and **Preview Flow** actions in the API Registry UI.
- Added backend endpoint: `POST /api/v1/api-registry/push-flow`.
- Registry flow now materialises into `ApiFlowMap` when a previous upload session exists.
- System Map gives curated Registry flow priority for matching API/endpoints.

## Usage
1. Open System Map.
2. Select API and endpoint.
3. Click **Push detected flow to API Registry**.
4. Edit flow steps manually in API Registry if required.
5. Click **Save Registry**.
6. Refresh System Map.

## Notes
- Re-upload/re-analyse older logs once for best trace and latency enrichment.
- Manual Registry flow acts as source of truth when logs do not contain enough topology markers.
