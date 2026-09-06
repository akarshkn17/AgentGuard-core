# AgentGuard Design Artifacts Compendium

**Date:** 2 September 2026

This document consolidates the formal design artifacts. The package also includes machine-readable schemas, OpenAPI, SQL, RBAC CSV, ADR files and Draw.io diagrams.


---

## Product Requirements Document (PRD)

## Product vision

AgentGuard is an enterprise AI application security platform that discovers AI/agentic assets, statically detects vulnerabilities and insecure capability paths, produces AI-BOM/provenance data, and manages findings across developer, CI/CD and centralized SaaS workflows.

## Product outcomes

1. Developers can detect Agent/MCP/tool/skill/RAG/model security issues before commit.
2. CI/CD pipelines can gate releases on new or policy-violating findings.
3. Security teams can centrally manage findings, ownership, exceptions, SLAs and trends.
4. Organizations can maintain an inventory/BOM of AI components and relationships.
5. Security analysts can understand source-to-sink and capability/provenance paths rather than isolated alerts.
6. Customers can integrate third-party security engines without fragmenting the user experience.

## Primary personas

- **Developer** - **Need:** Fast local feedback with code evidence and remediation
- **DevOps/Platform Engineer** - **Need:** Reliable CI integration, deterministic exit policy, low operational overhead
- **AppSec/AI Security Analyst** - **Need:** Triage, graph context, suppression, assignment, reports and historical trend
- **Security Manager** - **Need:** Risk posture, SLA, coverage and executive reporting
- **Tenant/Org Admin** - **Need:** Users, roles, projects, integrations, policies and data boundaries
- **Auditor** - **Need:** Read-only evidence, change history, approvals, exceptions and reports
- **Integration Service** - **Need:** API-based ingestion/export with scoped machine identity


## Core use cases

### UC-01 Local scan
A developer installs AgentGuard and scans a repository without connecting to SaaS.

### UC-02 IDE scan
An IDE extension calls a local machine-readable CLI/SDK interface and shows findings in the editor.

### UC-03 CI security gate
A pipeline scans a checkout, emits SARIF/JUnit/HTML and fails only when configured policy conditions are met.

### UC-04 Connected CI
A pipeline uploads normalized results to a tenant/project for central lifecycle management.

### UC-05 SaaS-managed scan
An authorized user creates a scan through UI/API. The platform queues a job and an isolated worker scans the source snapshot.

### UC-06 Vulnerability management
Analysts triage, assign, suppress, accept risk, resolve or reopen findings while preserving history.

### UC-07 AI inventory and AI-BOM
Security teams view discovered agents, tools, MCP, skills, models, RAG components and relationships, then export a BOM.

### UC-08 Provenance/attack paths
Analysts explore relationships and security overlays to identify reachability and blast radius.

### UC-09 Third-party engine
An administrator configures an approved external engine. Results appear through the same normalized finding model.

### UC-10 Custom dashboard/report
Users save widgets and generate role-specific reports without modifying scanner code.

## In scope for first enterprise release

- Core/CLI separation
- CI policy engine and major pipeline examples
- PostgreSQL-backed Platform API
- Entra authentication
- Tenant/project RBAC
- Scan ingestion and asynchronous scan workers
- Finding lifecycle
- AI inventory history
- AI-BOM export
- Customizable dashboard foundation
- HTML/JSON/SARIF/CSV/XLSX/PDF reporting
- Audit log
- Generic scanner adapter interface

## Later scope

- dedicated graph analytics service if required by scale
- customer-hosted workers
- deployment stamps for dedicated tenants
- full marketplace integrations
- advanced remediation automation
- enterprise SSO lifecycle automation/SCIM
- fine-grained policy language beyond initial policy rules

## Non-goals

- Replacing the existing AgentGuard detection logic during architecture refactor
- Building a custom identity provider
- Running arbitrary customer code in the web/API process
- Requiring cloud connectivity for local scanning
- Creating one microservice per feature in the first release

## Success measures

- Core installation has no web/SaaS dependency.
- Local scan output regression remains stable across extraction.
- CI scan startup and output are deterministic.
- Platform can ingest results from a remote/offline scanner.
- Tenant isolation tests prevent cross-tenant data access.
- UI communicates only through published APIs.
- External engine results require no UI-specific data model.
- 100% of finding lifecycle mutations are auditable.

---

## Feature Requirements

Priority: P0 = required for first enterprise platform, P1 = next, P2 = later.

- **FR-CORE-001** - **Area:** Core; **Requirement:** Scan a repository using existing native analyzers/rules without web/platform dependencies; **Priority:** P0
- **FR-CORE-002** - **Area:** Core; **Requirement:** Return a versioned `ScanResult` contract; **Priority:** P0
- **FR-CORE-003** - **Area:** Core; **Requirement:** Preserve stable finding fingerprints during architectural extraction; **Priority:** P0
- **FR-CORE-004** - **Area:** Core; **Requirement:** Continue inventory and relationship extraction; **Priority:** P0
- **FR-CORE-005** - **Area:** Core; **Requirement:** Support optional analyzer/LLM extensions without making them mandatory; **Priority:** P0
- **FR-CLI-001** - **Area:** CLI; **Requirement:** Install independently of Platform/UI; **Priority:** P0
- **FR-CLI-002** - **Area:** CLI; **Requirement:** Produce JSON, SARIF and HTML locally; **Priority:** P0
- **FR-CLI-003** - **Area:** CLI; **Requirement:** Produce CSV/XLSX/JUnit/PDF through reporting module; **Priority:** P1
- **FR-CLI-004** - **Area:** CLI; **Requirement:** Support deterministic exit policy; **Priority:** P0
- **FR-CLI-005** - **Area:** CLI; **Requirement:** Support machine-readable IDE mode; **Priority:** P1
- **FR-CLI-006** - **Area:** CLI; **Requirement:** Upload normalized result to Platform only when configured; **Priority:** P1
- **FR-CI-001** - **Area:** CI; **Requirement:** Support Jenkins example/template; **Priority:** P0
- **FR-CI-002** - **Area:** CI; **Requirement:** Support GitHub Actions; **Priority:** P0
- **FR-CI-003** - **Area:** CI; **Requirement:** Support Azure DevOps; **Priority:** P0
- **FR-CI-004** - **Area:** CI; **Requirement:** Support GitLab; **Priority:** P1
- **FR-CI-005** - **Area:** CI; **Requirement:** Publish pipeline-native artifacts and annotations; **Priority:** P1
- **FR-PLAT-001** - **Area:** Platform; **Requirement:** Multi-tenant organization/workspace/project model; **Priority:** P0
- **FR-PLAT-002** - **Area:** Platform; **Requirement:** Entra-based authentication; **Priority:** P0
- **FR-PLAT-003** - **Area:** Platform; **Requirement:** Resource-scoped RBAC; **Priority:** P0
- **FR-PLAT-004** - **Area:** Platform; **Requirement:** API/service-account authentication; **Priority:** P0
- **FR-PLAT-005** - **Area:** Platform; **Requirement:** Create, cancel, view and retry scan jobs; **Priority:** P0
- **FR-PLAT-006** - **Area:** Platform; **Requirement:** Accept uploaded scan results; **Priority:** P0
- **FR-PLAT-007** - **Area:** Platform; **Requirement:** Vulnerability lifecycle and history; **Priority:** P0
- **FR-PLAT-008** - **Area:** Platform; **Requirement:** Assignment, comments, suppressions, risk acceptance, SLA; **Priority:** P0
- **FR-PLAT-009** - **Area:** Platform; **Requirement:** Audit all administrative and finding-lifecycle mutations; **Priority:** P0
- **FR-PLAT-010** - **Area:** Platform; **Requirement:** Saved policies and scan profiles; **Priority:** P1
- **FR-WRK-001** - **Area:** Worker; **Requirement:** Consume immutable scan jobs from queue; **Priority:** P0
- **FR-WRK-002** - **Area:** Worker; **Requirement:** Use ephemeral workspace and resource/time limits; **Priority:** P0
- **FR-WRK-003** - **Area:** Worker; **Requirement:** Default-deny outbound network where practical; **Priority:** P0
- **FR-WRK-004** - **Area:** Worker; **Requirement:** Execute Core and approved adapter engines; **Priority:** P0
- **FR-WRK-005** - **Area:** Worker; **Requirement:** Destroy source workspace after result/artifact upload; **Priority:** P0
- **FR-INV-001** - **Area:** Inventory; **Requirement:** Maintain versioned AI asset inventory per project; **Priority:** P0
- **FR-INV-002** - **Area:** Inventory; **Requirement:** Track agent/tool/MCP/model/skill/RAG/memory identities; **Priority:** P0
- **FR-INV-003** - **Area:** Inventory; **Requirement:** Support ownership, approval and custom governance metadata; **Priority:** P1
- **FR-BOM-001** - **Area:** AI-BOM; **Requirement:** Export CycloneDX AI/ML-BOM; **Priority:** P0
- **FR-BOM-002** - **Area:** AI-BOM; **Requirement:** Export historical snapshot for a selected scan; **Priority:** P0
- **FR-GRF-001** - **Area:** Graph; **Requirement:** Store snapshot-scoped normalized nodes/edges; **Priority:** P0
- **FR-GRF-002** - **Area:** Graph; **Requirement:** Overlay findings/evidence onto graph; **Priority:** P1
- **FR-GRF-003** - **Area:** Graph; **Requirement:** Reachability and blast-radius analysis; **Priority:** P1
- **FR-GRF-004** - **Area:** Graph; **Requirement:** Risk-ranked attack paths; **Priority:** P2
- **FR-REP-001** - **Area:** Reports; **Requirement:** Generate JSON/SARIF/CSV/XLSX/JUnit/HTML/PDF; **Priority:** P1
- **FR-REP-002** - **Area:** Reports; **Requirement:** Support configurable report sections/templates; **Priority:** P1
- **FR-REP-003** - **Area:** Reports; **Requirement:** Generate self-contained HTML; **Priority:** P0
- **FR-UI-001** - **Area:** UI; **Requirement:** Separate web application consuming Platform API only; **Priority:** P0
- **FR-UI-002** - **Area:** UI; **Requirement:** Dashboard with configurable widgets; **Priority:** P1
- **FR-UI-003** - **Area:** UI; **Requirement:** Findings list/detail with evidence path and lifecycle; **Priority:** P0
- **FR-UI-004** - **Area:** UI; **Requirement:** Project/scan/inventory/BOM views; **Priority:** P0
- **FR-UI-005** - **Area:** UI; **Requirement:** Interactive provenance/attack path view; **Priority:** P1
- **FR-UI-006** - **Area:** UI; **Requirement:** Admin screens for roles, integrations and policies; **Priority:** P1
- **FR-PLG-001** - **Area:** Plugins; **Requirement:** Generic scanner engine adapter contract; **Priority:** P0
- **FR-PLG-002** - **Area:** Plugins; **Requirement:** Normalize external findings to canonical schema; **Priority:** P0
- **FR-PLG-003** - **Area:** Plugins; **Requirement:** Isolate engine-specific credentials/configuration; **Priority:** P0
- **FR-PLG-004** - **Area:** Plugins; **Requirement:** Support SkillSpector through generic contract; **Priority:** P1
- **FR-PLG-005** - **Area:** Plugins; **Requirement:** Add Cisco/other engines without Core/UI changes; **Priority:** P1


## Non-functional requirements

- **NFR-SEC-001** - **Requirement:** Tenant-scoped data access must fail closed when tenant context is missing.
- **NFR-SEC-002** - **Requirement:** Customer source must not be processed by the long-lived API process.
- **NFR-SEC-003** - **Requirement:** Secrets are stored in Key Vault or equivalent managed secret store.
- **NFR-SEC-004** - **Requirement:** All privileged actions are auditable.
- **NFR-SEC-005** - **Requirement:** Worker images run non-root, read-only filesystem where feasible, with bounded CPU/memory/time.
- **NFR-REL-001** - **Requirement:** Scan job orchestration is idempotent and retry-safe.
- **NFR-REL-002** - **Requirement:** A failed/partial scan must not resolve previously open findings.
- **NFR-PERF-001** - **Requirement:** API list endpoints use pagination and server-side filters.
- **NFR-PERF-002** - **Requirement:** Large reports and scans execute asynchronously.
- **NFR-OBS-001** - **Requirement:** API, worker and integration operations emit structured logs, metrics and traces.
- **NFR-COMP-001** - **Requirement:** Audit logs and evidence retention are configurable by tenant policy.
- **NFR-EXT-001** - **Requirement:** Contracts are versioned and backwards compatibility is documented.


---

## System Context Architecture

## Purpose
Defines AgentGuard's external actors and systems without implementation detail.

## Actors
- Developer
- Security Analyst
- Security Manager
- Org/Tenant Administrator
- Auditor
- CI/CD service identity
- Platform operator

## External systems
- Source control providers
- CI/CD platforms
- Microsoft Entra ID / customer identity provider federation
- Ticketing/notification systems
- External scanner engines
- Optional LLM provider
- Azure platform services

## Context

```text
Developers --------> Local CLI/IDE -----+
                                         |
CI/CD --------------> CI Adapter --------+----> AgentGuard Scanner
                                         |           |
                                         |           +--> optional result upload
                                         v
Security/Admin users ----------------> AgentGuard SaaS Platform <---- Entra ID
                                         |
                                         +--> SCM/CI integrations
                                         +--> External scanners
                                         +--> Jira/ServiceNow/notifications
                                         +--> Reports/API exports
```

See editable diagram: `diagrams/01_system_context.drawio`.

---

## Container Architecture

This uses the C4 meaning of **container**: an independently running application/process, not only a Docker container.

- **Core library** - **Responsibility:** static analysis; **Technology direction:** Python package; **Persistent state:** none required
- **CLI** - **Responsibility:** local developer/pipeline interface; **Technology direction:** Python CLI/standalone binary; **Persistent state:** local config/cache only
- **Platform API** - **Responsibility:** SaaS control plane; **Technology direction:** FastAPI or equivalent; **Persistent state:** PostgreSQL
- **Scan Worker** - **Responsibility:** isolated execution; **Technology direction:** hardened container/job; **Persistent state:** ephemeral workspace
- **Web UI** - **Responsibility:** browser app; **Technology direction:** React/Next.js or equivalent; **Persistent state:** none; API only
- **Graph module/service** - **Responsibility:** graph queries/derived paths; **Technology direction:** initially Platform module; extract later; **Persistent state:** graph snapshot/index
- **Report worker/module** - **Responsibility:** heavy report rendering; **Technology direction:** library locally; async worker in SaaS; **Persistent state:** Blob artifacts
- **Plugin adapters** - **Responsibility:** third-party scanner integration; **Technology direction:** worker-side SDK/plugins; **Persistent state:** engine artifacts only


## Primary communication

- CLI -> Core: in-process Python contract.
- CI adapter -> CLI: process invocation or action wrapper.
- UI -> Platform: HTTPS JSON API.
- Platform -> Worker: queue job reference.
- Worker -> Platform: authenticated result ingestion/API or blob + manifest.
- Platform -> PostgreSQL/Blob/graph store: private service connections.

See editable diagram: `diagrams/02_container_architecture.drawio`.

---

## Component Architecture

## Core components
- RepositoryWalker
- RuleStore
- PythonProjectAnalyzer
- TreeSitterAnalyzer
- ConfigAnalyzer
- Taint/Dataflow Engine
- InventoryDiscoverer
- LLMReviewer extension
- FindingNormalizer
- ScanCoordinator

## CLI components
- command router
- config/profile loader
- local result writer
- policy/exit evaluator
- platform client

## Platform components
- AuthN integration
- Authorization service
- Tenant/workspace/project service
- Scan job service
- Result ingestion service
- Finding lifecycle service
- Inventory service
- Dashboard service
- Reporting service
- Integration configuration service
- Audit service

## Worker components
- job consumer
- source snapshot provider
- sandbox/workspace manager
- engine runner
- plugin host
- result normalizer
- artifact uploader

## UI components
- shell/navigation
- dashboard builder
- projects/scans
- findings/evidence
- inventory/BOM
- graph explorer
- reports
- administration

See editable diagram: `diagrams/03_component_architecture.drawio`.

---

## Data Flow Diagrams

## DFD-1 Local scan
1. Developer invokes CLI.
2. CLI builds `ScanRequest`.
3. Core reads repository as untrusted input.
4. Core creates canonical `ScanResult`.
5. Reporting renders local artifacts.
6. Optional platform upload occurs only when explicitly configured.

## DFD-2 CI/CD scan
1. Pipeline checks out source.
2. CI adapter invokes CLI.
3. Core scans local checkout.
4. Policy engine evaluates findings.
5. Pipeline receives exit code and artifacts.
6. Connected mode uploads `ScanResult` to Platform.

## DFD-3 SaaS-managed scan
1. Authorized user/API creates scan.
2. Platform stores job metadata and queues immutable request.
3. Worker receives job.
4. Worker obtains source snapshot in ephemeral workspace.
5. Worker executes Core and configured external engines.
6. Worker normalizes result and uploads artifacts.
7. Platform transactionally ingests scan metadata, occurrences, inventory and relationships.
8. Lifecycle resolver compares completed result with previous complete scan.
9. Graph/report jobs are triggered asynchronously.

## DFD-4 Third-party scanner
1. Platform policy selects engine.
2. Worker/plugin host loads engine adapter.
3. Adapter executes vendor API/CLI according to approved configuration.
4. Adapter returns `EngineResult`.
5. Normalizer maps vendor schema to canonical finding/entity/relationship contracts.
6. UI renders generic result and shows `engine_id` as provenance.

See editable diagram: `diagrams/04_data_flows.drawio`.

---

## Azure Deployment Architecture

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

---

## API Specification

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

---

## Scan Result Contract

## Intent
`ScanResult` is the stable interchange object between scanner execution and every consumer. Core should not persist platform workflow fields into this object.

## Top-level structure

```json
{
  "contract_version": "1.0",
  "scan": {},
  "engines": [],
  "findings": [],
  "inventory": [],
  "relationships": [],
  "artifacts": [],
  "metrics": {},
  "errors": []
}
```

## Compatibility rules
- New optional fields may be added in minor versions.
- Removing/renaming fields requires a major contract version.
- Findings retain a scanner-stable fingerprint independent of SaaS database IDs.
- File locations are repository-relative, not machine absolute paths.
- Engine identity and engine version are mandatory for provenance.
- Partial scans declare completeness explicitly.

Machine-readable schemas are in `schemas/`.

---

## Finding Schema

A canonical finding must be able to represent deep dataflow findings, structural/config findings and normalized external-engine findings.

Required fields:
- `fingerprint`
- `engine_id`
- `rule_id`
- `title`
- `severity`
- `analysis_type`
- `location`

Important optional fields:
- confidence
- description
- message
- category
- framework mappings
- CWE
- source/sink
- evidence path
- code snippets
- remediation
- references
- related asset IDs
- vendor/original payload reference

Platform lifecycle status is deliberately not part of the scanner's canonical finding identity. The platform joins a finding fingerprint to lifecycle state.

---

## Inventory Schema

Canonical `InventoryEntity` is a discovered technical asset, not a platform ownership record.

Required:
- `entity_id`
- `entity_type`
- `name`
- `source_evidence`

Examples of `entity_type`:
- agent
- sub_agent
- orchestrator
- tool
- function_tool
- mcp_server
- mcp_client
- mcp_tool
- mcp_resource
- mcp_prompt
- skill
- plugin
- model
- embedding_model
- model_provider
- retriever
- vector_store
- rag_pipeline
- memory
- checkpoint_store
- prompt
- guardrail
- api_endpoint
- identity
- deployment

The platform may enrich the asset with owner, business service, approval status, tags and custom governance metadata without changing the scanner identity.

---

## Graph Schema

## Graph node
A graph node references an inventory entity or a derived security object.

Node classes:
- asset
- identity
- data
- finding
- control

## Graph edge
Each edge contains:
- `edge_id`
- `source_id`
- `target_id`
- `relationship_type`
- confidence
- source evidence
- snapshot/scan ID
- attributes

## Security overlay
Derived edge/node metadata can include:
- privilege level
- externally influenced
- data classification
- internet reachable
- vulnerable
- sensitive sink
- trust zone

The raw graph remains immutable per scan snapshot. Attack-path/risk calculations are derived views so algorithms can evolve without rewriting source evidence.

---

## Database Design

## Local mode
SQLite remains acceptable for local/offline scan history. It must be treated as a local implementation of repository interfaces, not as the SaaS schema.

## SaaS system of record
Use PostgreSQL for control-plane metadata and finding lifecycle.

## Logical entities

### Identity/tenant
- tenants
- users (local profile mapped to external subject, not passwords)
- groups (optional platform representation)
- role_bindings
- service_accounts/oauth_clients metadata

### Application model
- workspaces
- projects
- repositories
- project_integrations
- scan_profiles

### Scanning
- scans
- scan_engines
- scan_artifacts
- scan_errors

### Findings
- findings (durable logical issue)
- finding_occurrences
- finding_events
- comments
- suppressions
- risk_acceptances
- assignments

### AI inventory
- inventory_entities
- inventory_versions
- inventory_occurrences
- relationships
- governance_flags

### Platform
- dashboard_definitions
- report_jobs
- integration_configs (non-secret metadata)
- audit_events

## Multi-tenant data rule
Every tenant-scoped table includes `tenant_id`, and repositories enforce tenant filtering through a mandatory request context. Consider PostgreSQL Row Level Security as defense in depth, not as the only authorization layer.

## Finding identity
- scanner `fingerprint` is stable technical identity within a project.
- platform `finding_id` is an opaque UUID.
- unique constraint: `(tenant_id, project_id, fingerprint)`.
- occurrences are immutable per scan.

## Scan closure
Only a **completed** scan can resolve previous occurrences by absence. `partial`, `failed` and `cancelled` scans do not close earlier findings.

See `postgres_schema.sql` for starter DDL and `diagrams/06_data_model.drawio` for an editable ER view.

---

## RBAC Design

## Authentication vs authorization
Microsoft Entra authenticates the person/workload. AgentGuard Platform authorizes actions on AgentGuard resources.

## Roles

### PlatformOwner
Operator-level platform administration. Not normally a customer tenant role.

### OrgAdmin
Manages tenant users/bindings, projects, integrations and policies.

### SecurityAdmin
Manages security policies, scan profiles, suppressions and risk-acceptance policy.

### SecurityAnalyst
Views all tenant projects, triages findings, creates comments/assignments/reports.

### ProjectAdmin
Manages one or more projects and their scan configuration/integrations.

### Developer
Views assigned/accessible projects, runs scans, views findings, can comment; cannot approve risk acceptance.

### Auditor
Read-only access to evidence, reports, audit log and historical state.

### IntegrationService
Machine role with explicit scopes such as result ingestion, scan creation or export.

## Authorization algorithm
1. Validate token and issuer/audience.
2. Resolve effective tenant.
3. Load subject role bindings for requested resource hierarchy.
4. Evaluate action against role permissions.
5. Apply resource attributes/policy restrictions.
6. Record privileged mutation in audit log.
7. Deny by default.

See `rbac_matrix.csv` and editable auth diagram `diagrams/07_auth_rbac.drawio`.

---

## AgentGuard Platform Threat Model

## Protected assets
- customer source repositories/snapshots
- findings/evidence
- AI inventory and provenance graph
- credentials for SCM/external scanners
- tenant identities and RBAC configuration
- reports and exports
- audit history
- worker execution infrastructure

## Trust boundaries
1. Internet -> Edge/WAF/APIM
2. Identity provider -> Platform session/token validation
3. UI/client -> Platform API
4. Platform API -> Queue
5. Queue -> Worker
6. Worker -> customer source artifact
7. Worker -> external scanner/LLM endpoints
8. Platform -> database/blob/graph storage
9. Tenant A -> shared infrastructure -> Tenant B

## Priority threats and controls

- **Cross-tenant authorization failure** - **Example:** user guesses another project ID; **Key controls:** tenant context, resource authorization, RLS defense-in-depth, negative tests
- **Malicious scanned repository** - **Example:** zip bomb, parser DoS, crafted file, malicious build config; **Key controls:** no code import/execute by default, limits, sandbox, parser hardening, timeouts
- **Worker escape** - **Example:** scanner/plugin exploit reaches host; **Key controls:** rootless container/job, seccomp/runtime controls, no host mounts/socket, patching
- **Credential theft** - **Example:** repository reads worker secrets; **Key controls:** short-lived per-job credentials, minimal env exposure, managed identity, no shared static secrets
- **Data exfiltration** - **Example:** malicious source causes outbound network use; **Key controls:** deny egress by default, allow-list per engine, proxy logging
- **Queue tampering** - **Example:** arbitrary command injected as scan request; **Key controls:** typed immutable job schema, signed/authenticated queue identity, no shell string commands
- **Result spoofing** - **Example:** client uploads forged engine identity; **Key controls:** authenticated ingestion, engine claims/policy, provenance metadata, optional signed result manifests
- **Stored XSS in evidence** - **Example:** source snippet rendered unsafely in UI/report; **Key controls:** output encoding, CSP, sanitized HTML, never trust code snippets
- **Report injection** - **Example:** finding text becomes active HTML/CSV formula; **Key controls:** template escaping, CSP, formula-neutralization for CSV/XLSX, safe PDF renderer
- **RBAC escalation** - **Example:** project admin grants org admin; **Key controls:** permission boundary on role management, separate admin scopes, audit
- **Suppression abuse** - **Example:** developer hides critical issue indefinitely; **Key controls:** role restriction, mandatory reason/expiry, policy controls, audit, manager reporting
- **Supply-chain compromise** - **Example:** poisoned scanner/plugin image; **Key controls:** signed artifacts, SBOM, image scanning, pinned deps, provenance attestations
- **LLM data leakage** - **Example:** source/evidence sent to external provider; **Key controls:** explicit opt-in, data classification policy, tenant configuration, redaction, provider allow-list
- **Denial of service** - **Example:** enormous repo/scan flood; **Key controls:** rate limits, queue quotas, per-tenant concurrency, file/size/time limits
- **SSRF from integrations** - **Example:** user config points platform to metadata/internal hosts; **Key controls:** outbound proxy, URL allow-list, network segmentation, DNS/IP validation
- **Audit tampering** - **Example:** privileged admin removes evidence of change; **Key controls:** append-only audit design, restricted delete, external log export/retention


## Security acceptance tests
- cross-tenant IDOR test suite for every resource endpoint
- token from wrong issuer/audience rejected
- missing tenant context rejected
- worker cannot reach internet without explicit egress policy
- worker cannot access another job workspace
- source code snippets render as text, not HTML
- CSV cells beginning with formula characters are neutralized
- failed scan does not close findings
- suppression permissions/expiry enforced
- plugin cannot read unrelated integration credentials

---

## UI/UX Specification

## UX principles
1. Show the security story, not only counts.
2. Preserve developer evidence close to the finding.
3. Make scope visible at all times: tenant -> workspace -> project -> branch/scan.
4. Distinguish scanner facts from workflow decisions.
5. Graphs must be explorable and filterable, not decorative.
6. Dashboards are configurable but ship with strong role-based defaults.

## Primary navigation
- Overview
- Projects
- Scans
- Findings
- AI Inventory
- AI-BOM
- Provenance / Attack Paths
- Reports
- Integrations
- Policies
- Administration

## Dashboard
Default cards:
- open Critical/High
- new findings (7/30 days)
- overdue SLA
- scan health/failures
- AI assets discovered
- unapproved agents/models/tools

Default charts:
- new vs resolved trend
- severity by project
- finding categories
- top risky AI assets
- scan coverage trend

Users can add/remove/reorder widgets and save personal/team dashboards.

## Finding detail
Layout:
1. title/severity/status/engine/rule
2. location and code context
3. evidence path / source-to-sink flow
4. related AI assets and graph context
5. remediation and references
6. lifecycle history
7. assignment/comments/suppression/risk acceptance
8. occurrence history across scans

## Graph explorer
- left filter panel: entity type, severity, trust zone, approval, relationship type
- canvas: zoom/pan/select; edge arrows and legend
- right detail panel: node/edge evidence, source location, related findings
- path mode: choose start/end or "show risky paths"
- snapshot selector: compare current vs previous scan

## Report builder
- audience preset: Executive / AppSec / Developer / Audit
- selectable sections
- project/scan/time filters
- export format
- report preview

## Accessibility
- WCAG 2.2 AA target
- keyboard-operable graph fallback/list representation
- color is never the only severity indicator
- accessible table headers and focus states

See `diagrams/08_ui_information_architecture.drawio`.

---

## Team Development Guide

## Repository strategy
Use a monorepo initially. Packages and services have owners and independent CI jobs.

## Ownership
- `packages/core`: Scanner team
- `packages/contracts`: architecture/shared ownership; CODEOWNERS review required
- `packages/cli`: developer tooling team
- `packages/reporting`: reporting/platform shared
- `packages/plugin-sdk`: integration team
- `services/platform-api`: platform/backend team
- `services/scan-worker`: platform/security engineering
- `apps/web`: frontend team
- `integrations/*`: integration owners
- `deploy/azure`: cloud/platform engineering

## Branch/PR policy
- short-lived feature branches
- conventional commit or agreed commit style
- PR must include tests
- contract/schema changes require compatibility note
- migrations require forward/backward deployment consideration
- rules/scan behavior changes require golden-repository update and security review

## Testing pyramid

### Core
- unit tests
- analyzer/rule unit tests
- golden repository regression tests
- fingerprint stability tests
- malformed/untrusted input tests

### Contracts
- JSON Schema validation
- backward compatibility fixtures
- serializer/deserializer roundtrip

### Platform
- service unit tests
- repository/database integration tests
- authorization negative tests
- lifecycle state-machine tests
- API contract tests

### Worker
- sandbox integration tests
- timeout/resource limit tests
- cleanup tests
- plugin isolation tests

### UI
- component tests
- API mock tests
- accessibility tests
- E2E user journeys

## Definition of done
A change is complete when:
- implementation and tests pass;
- security/tenant boundary impact considered;
- metrics/logs added for operational changes;
- API/schema docs updated;
- migration/rollback described when applicable;
- no forbidden dependency introduced;
- relevant ADR updated/added for significant decision.

## Dependency enforcement
Add architecture tests/lint rules so Core cannot import packages from Platform/UI or cloud provider SDKs.

## Versioning
- Core/CLI semantic versioning.
- Contracts carry explicit contract version.
- Platform API versioned under `/api/v1`.
- Database schema managed by migrations.
- Engine adapter compatibility declares supported contract versions.

## Release artifacts
- signed Python wheels/packages
- optional signed standalone CLI binary
- signed container images
- SBOM for release artifacts
- provenance/attestation where build system supports it
- release notes and migration notes

---

## Implementation Roadmap

## Milestone 0 - Regression safety
**Deliverables**
- golden repositories
- current result fixtures
- fingerprint stability tests
- inventory/BOM fixtures

**Exit criterion:** architectural refactor can prove no unexpected core scan behavior change.

## Milestone 1 - Contracts
**Deliverables**
- Contracts package
- JSON Schemas
- Core adapter returning `ScanResult`
- compatibility tests

## Milestone 2 - Core/CLI packaging separation
**Deliverables**
- `packages/core`
- `packages/cli`
- Core minimal dependencies
- CLI install/build pipeline
- local SQLite repository implementation outside scanner orchestration

## Milestone 3 - CI and reports
**Deliverables**
- policy/exit engine
- SARIF/JSON/HTML regression
- CSV/XLSX/JUnit/PDF renderers
- GitHub Actions, Jenkins and Azure DevOps integrations

## Milestone 4 - Platform MVP
**Deliverables**
- PostgreSQL schema/migrations
- Entra authentication
- tenant/project model
- RBAC
- result upload API
- scan/finding/inventory read APIs
- finding lifecycle/audit

## Milestone 5 - SaaS scan orchestration
**Deliverables**
- Service Bus
- worker image
- source snapshot abstraction
- sandbox limits/egress policy
- normalized ingestion
- retries/dead letter handling

## Milestone 6 - Web UI
**Deliverables**
- separate frontend
- overview/project/scan/finding/inventory screens
- admin/RBAC views
- dashboard widget model

## Milestone 7 - Graph and ecosystem
**Deliverables**
- graph snapshot/query API
- attack-path/reachability features
- plugin SDK
- SkillSpector migration to generic adapter
- first additional external scanner adapter

## Recommended team parallelization
After Milestone 1:
- Core team: M2/M3 scanner/CLI
- Platform team: M4
- Cloud/security team: M5 design and sandbox PoC
- Frontend team: API mocks and M6 design
- Integration team: CI adapters/plugin SDK

---

## Architecture Decision Records

The package includes eight ADRs under `09_adrs/` covering monorepo structure, Core independence, asynchronous workers, Entra identity, PostgreSQL, generic plugins, graph service timing and tenant isolation tiers.