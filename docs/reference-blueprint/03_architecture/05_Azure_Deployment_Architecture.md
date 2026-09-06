# Azure Deployment Architecture

## Recommended first production topology

### Edge and identity
- Azure Front Door Premium with WAF for public edge.
- Azure API Management for API gateway, throttling, versioning and external API policy.
- Microsoft Entra ID for workforce identities; External ID/federation where needed for customer identities.

### Application
- Web UI as a separate container/static frontend.
- Platform API as an independently deployable container.
- Scan Worker as isolated job/container workload.
- Optional graph service when extracted.

### Messaging/data
- Azure Service Bus for scan jobs and retry/dead-letter behavior.
- Azure Database for PostgreSQL for tenant/project/scan/finding lifecycle metadata.
- Azure Blob Storage for uploaded source snapshots when permitted, raw engine artifacts, HTML/PDF reports and exports.
- Graph storage initially can be relational adjacency/snapshot tables; evaluate a dedicated graph store only after query/scale evidence.

### Security/operations
- Azure Key Vault for secrets/keys.
- Managed Identity/Workload Identity for service-to-service Azure access.
- ACR for signed/scanned images.
- Azure Monitor/Application Insights/Log Analytics.
- Private Endpoints and network controls for data services.
- Defender for Cloud/Container protections according to enterprise baseline.

## Worker security baseline
- ephemeral workspace
- non-root
- read-only root filesystem where feasible
- no Docker socket
- CPU/memory/pid/file/time limits
- default-deny egress; explicit allow list when an engine requires internet
- per-job credentials with shortest practical lifetime
- source deleted on completion/failure cleanup
- never trust repository build scripts by default

## Multi-tenancy
Use a tiered model instead of one claim that all tenants are isolated the same way.

1. Shared standard tier: shared control plane and database with tenant-enforced rows; isolated jobs.
2. Enhanced tier: dedicated worker pool/node boundary and optional dedicated storage/database boundary.
3. Dedicated tier: deployment stamp with customer-specific resources.

See editable diagram: `diagrams/05_azure_deployment.drawio`.
