# API Specification

Base: `/api/v1`

## API principles
- OIDC/OAuth2 bearer authentication.
- Every tenant-scoped route resolves tenant context server-side.
- Resource IDs never substitute for authorization.
- Cursor or page-based pagination for collections.
- Idempotency key for scan creation/result ingestion where needed.
- RFC 7807-style problem responses recommended.
- OpenAPI is the source of truth for UI/SDK generation.

## Major resources

### Organizations/workspaces/projects
- `GET /organizations`
- `GET /projects`
- `POST /projects`
- `GET /projects/{project_id}`

### Scans
- `POST /projects/{project_id}/scans`
- `GET /scans/{scan_id}`
- `POST /scans/{scan_id}/cancel`
- `POST /scans/{scan_id}/retry`
- `POST /projects/{project_id}/scan-results` - upload normalized offline/CI result

### Findings
- `GET /findings`
- `GET /findings/{finding_id}`
- `PATCH /findings/{finding_id}`
- `POST /findings/{finding_id}/comments`
- `POST /findings/{finding_id}/suppressions`
- `POST /findings/{finding_id}/risk-acceptance`

### Inventory/BOM/graph
- `GET /projects/{project_id}/inventory`
- `GET /scans/{scan_id}/aibom`
- `GET /scans/{scan_id}/graph`
- `POST /scans/{scan_id}/graph/query`

### Reports/dashboards
- `POST /reports`
- `GET /reports/{report_id}`
- `GET /dashboards`
- `POST /dashboards`

### Admin/integrations
- `GET /role-bindings`
- `POST /role-bindings`
- `GET /integrations`
- `POST /integrations`
- `GET /audit-events`

A starter OpenAPI contract is provided in `openapi.yaml`.
