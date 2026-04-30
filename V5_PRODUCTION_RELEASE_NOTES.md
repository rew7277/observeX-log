# ObserveX V5 Production Release Notes

## Included fixes

1. Dashboard and Log Search persistence
   - Added `autoBootFromDB()` to reload recent persisted sessions from `/history` after page refresh.
   - Dashboard, Flow Analytics and Log Search no longer depend only on the in-memory `_allRows` state.

2. Curated Topology persistence
   - Added `manual_flow_nodes_json` to `ApiRegistry`.
   - Added runtime database migration for PostgreSQL and SQLite.
   - Added `/api/v1/topology/push` to persist source-of-truth topology nodes.
   - System Map now prefers curated topology nodes before auto-generated downstream flow.

3. API Registry UI upgrade
   - Added Curated Topology Flow textarea.
   - Added Preview Flow, Use Selected Topology, and Push Topology → Registry actions.
   - Registry edit now reloads saved curated topology nodes.

4. Noise reduction
   - Curated topology push ignores processor/internal event IDs.
   - System Map continues using existing API inventory validation to avoid noisy nodes.

## Railway deployment notes

Required variables:

- `DATABASE_URL`
- `DATABASE_PUBLIC_URL` optional but recommended for debugging
- `JWT_SECRET`

Deployment:

1. Push this ZIP content to GitHub.
2. Connect GitHub repo to Railway.
3. Attach PostgreSQL service.
4. Add required variables.
5. Deploy using the included Dockerfile.

Health check path: `/health`
