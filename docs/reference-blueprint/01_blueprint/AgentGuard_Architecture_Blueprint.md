# AgentGuard Enterprise Architecture Blueprint

**Status:** Proposed target architecture for the next major AgentGuard evolution  
**Date:** 2 September 2026  
**Scope:** Architecture and design only. The existing detection engine is not changed by this blueprint.  
**Repository reviewed:** `akarshkn17/AgentGuard`

## 1. Why this blueprint exists

AgentGuard already has a useful static security scanning engine for AI/agentic applications. The current project includes rules, project-wide Python analysis, Tree-sitter/config analysis, taint/evidence paths, AI inventory, provenance relationships, an AI-BOM generator, SQLite persistence, CLI commands, a FastAPI UI and an external SkillSpector adapter.

That is a strong MVP, but those capabilities currently ship inside one Python distribution. The next step is not to rewrite the scanner. The next step is to give each concern a clean boundary so the same scan engine can be consumed safely in three ways:

1. **Developer/local use** - install AgentGuard and scan locally from terminal or IDE.
2. **CI/CD use** - run the same scanner in Jenkins, GitHub Actions, Azure DevOps, GitLab and similar pipelines.
3. **Enterprise SaaS use** - centrally manage projects, scans, findings, users, RBAC, dashboards, reports, AI inventory, AI-BOM, provenance/attack paths and third-party scanner integrations.

The key principle is:

> **The scanner finds security facts. The platform manages those facts. The UI displays and operates the platform.**

## 2. The beginner mental model

Think of AgentGuard as two products that share one security engine.

```text
AGENTGUARD SCANNER                         AGENTGUARD PLATFORM
------------------                         -------------------
Core scan engine                           Authentication / RBAC
CLI                                        Organizations / Projects
IDE integration            results         Scan management
CI/CD integration        ------------->    Vulnerability management
Offline reporting                           AI inventory / AI-BOM
                                             Provenance / attack paths
                                             Integrations / tickets
                                             Dashboards / reporting
                                             Web UI
```

The scanner product can work even if the SaaS platform does not exist. The SaaS platform can accept normalized results from AgentGuard Core and from approved external scanners.

## 3. How this resembles mature market tools

The target pattern is intentionally similar to mature AppSec products, while keeping AgentGuard's AI-specific capabilities.

| Market pattern | What it demonstrates | AgentGuard interpretation |
|---|---|---|
| Snyk supports CLI, IDE and CI/CD integrations in addition to a central platform | Security scanning can be embedded at multiple SDLC stages | One AgentGuard Core should power local, IDE and pipeline use |
| Snyk recommends CLI-based CI/CD integration for flexible pipeline use | CI adapters do not need a separate detection engine | AgentGuard CI integrations should wrap the same CLI/Core |
| Semgrep supports local CLI scans and uploading findings into its AppSec Platform | Local/offline scan and central management can coexist | AgentGuard can scan locally and optionally upload normalized results |
| Checkmarx One exposes a standalone CLI that can manage projects/scans/results against its server and acts as the backbone for plugins | CLI and plugin surfaces can be stable clients over platform APIs | AgentGuard can later offer both local-core commands and platform-connected commands |

AgentGuard should not copy any vendor implementation. The lesson is architectural: mature scanning products separate **analysis**, **developer interfaces**, **pipeline adapters**, **control-plane services** and **presentation**.

## 4. Current AgentGuard architecture

The current release is best described as a modular monolith.

```text
src/agentguard/

scanner.py + analyzers + rules + inventory
                 |
                 v
             Store/db.py
                 |
        +--------+---------+
        |                  |
        v                  v
      CLI              FastAPI UI
```

This is appropriate for an MVP, workstation scanner, CI worker or private pilot. The problem is not that the source files are badly organized. The problem is that packaging and runtime boundaries are not yet explicit:

- one Python package contains scanner, CLI and web UI dependencies;
- the UI reads the same Store abstraction directly;
- SQLite is the persistence boundary;
- CLI commands know how to launch the UI;
- external scanner integration is implemented as a specific adapter rather than a generalized plugin contract;
- authentication, tenant isolation and enterprise RBAC are not yet a SaaS control plane;
- provenance visualization and graph analytics are still coupled to the local application model.

## 5. Target architecture - the five primary layers

### Layer 1 - AgentGuard Core

**Responsibility:** Security analysis only.

Core owns:

- file discovery and repository normalization;
- rules and rule loading;
- Python AST analysis;
- Tree-sitter/language analysis;
- project-wide/interprocedural taint analysis;
- structural and configuration analysis;
- AI inventory discovery;
- evidence paths;
- canonical findings, assets and relationships;
- optional LLM review behind a defined extension point.

Core does **not** own:

- users;
- organizations;
- RBAC;
- HTTP sessions;
- Azure;
- dashboards;
- tickets;
- vulnerability workflow;
- browser rendering.

Core accepts a `ScanRequest` and returns a `ScanResult`.

### Layer 2 - AgentGuard CLI / Developer Interface

**Responsibility:** Make Core easy to use from a developer machine.

CLI owns:

- command parsing;
- terminal output;
- local config discovery;
- selecting rules and profiles;
- local file outputs;
- local exit codes;
- optional authenticated upload to the platform;
- IDE-friendly machine-readable mode.

The CLI calls Core. It does not reimplement detection.

Example future commands:

```bash
agentguard scan .
agentguard scan . --format sarif --output agentguard.sarif
agentguard scan . --baseline main --fail-on new-high
agentguard inventory .
agentguard aibom . --format cyclonedx
agentguard login
agentguard upload result.json
```

### Layer 3 - CI/CD Integrations

**Responsibility:** Adapt the CLI/Core to pipeline systems.

CI/CD integrations own:

- pipeline-specific configuration;
- checkout/context discovery;
- caching installation artifacts;
- translating policy outcomes to pass/fail;
- publishing SARIF/JUnit/HTML artifacts;
- PR annotations where supported;
- optional result upload to AgentGuard Platform.

They do not own scanner logic.

The recommended default model is:

```text
Pipeline -> AgentGuard CLI -> AgentGuard Core -> result files
                                         |
                                         +--> optional upload to Platform
```

### Layer 4 - AgentGuard Platform

**Responsibility:** Enterprise security management and scan orchestration.

Platform owns:

- tenant/organization/workspace model;
- projects and repositories;
- users, service accounts and RBAC;
- scan configuration and scheduling;
- asynchronous scan jobs;
- vulnerability lifecycle;
- assignment, SLA, suppressions, exceptions and comments;
- baseline and trend analytics;
- normalized ingestion from AgentGuard and external scanners;
- report definitions;
- dashboards and saved widgets;
- AI inventory/AI-BOM history;
- integration configuration;
- audit trail;
- API keys/OAuth client credentials;
- organization policy.

Platform does not parse source code directly. It asks isolated workers to run scanners.

### Layer 5 - AgentGuard UI

**Responsibility:** Browser-based user experience.

UI owns:

- dashboard screens;
- findings tables and detail pages;
- project and scan views;
- AI inventory and AI-BOM views;
- provenance/attack path visualization;
- report builder;
- integration and administration screens;
- user-configurable widgets.

UI calls Platform APIs. It never imports Core or connects directly to the database.

## 6. Supporting components that make the five layers work

The five layers are the product mental model. The implementation also needs supporting modules.

### 6.1 Contracts package

`agentguard-contracts` defines versioned data structures shared between Core, CLI, workers and Platform.

Minimum contracts:

- `ScanRequest`
- `ScanResult`
- `Finding`
- `EvidenceStep`
- `InventoryEntity`
- `Relationship`
- `EngineResult`
- `ReportManifest`
- `GraphSnapshot`

This package is one of the most important architecture artifacts because it prevents modules from depending on each other's internal implementation.

### 6.2 Scanner Worker

For SaaS, the Platform should not execute arbitrary repositories in the API process.

```text
Platform API -> queue -> isolated Scan Worker -> Core / external engine
```

The worker:

- obtains an immutable repository snapshot or artifact reference;
- creates an ephemeral read-only scan workspace;
- applies resource limits;
- runs selected engines;
- normalizes results;
- uploads result/artifact manifests;
- destroys the workspace.

### 6.3 Reporting module/service

A common report model should generate:

- console/table;
- JSON;
- SARIF;
- CSV;
- XLSX;
- JUnit XML;
- CycloneDX AI/ML-BOM;
- HTML;
- PDF;
- executive and technical templates.

Local CLI can use the reporting package directly. SaaS can expose the same report model through a report service/job.

### 6.4 Plugin SDK / engine adapters

External scanners must not be hard-coded into the platform.

Every scanner adapter follows the same lifecycle:

```text
prepare -> execute -> collect -> normalize -> attach artifacts
```

Each engine returns `EngineResult` containing normalized `Finding`, `InventoryEntity`, `Relationship` and artifact records.

This is how AgentGuard can add integrations such as NVIDIA SkillSpector, Cisco AI Defense or customer-specific tools without changing Core detection code or UI rendering logic.

### 6.5 Graph domain

Inventory and provenance are related but not identical.

- **Inventory** answers: What AI assets exist?
- **Provenance** answers: How are those assets connected?
- **Attack path** answers: Which relationships combine into a security-relevant path?

The graph domain accepts normalized assets, relationships, findings and evidence paths. It produces graph snapshots and derived analytics such as reachability, blast radius and risk-ranked paths.

## 7. Allowed dependency directions

This rule should be enforced in CI.

```text
contracts
   ^
   |
core <----- cli
 ^           ^
 |           |
worker       +---- CI adapters
 |
 v
platform API <----- UI
```

More explicitly:

**Allowed**

- CLI -> Core
- CLI -> Contracts
- Worker -> Core
- Worker -> Plugin SDK
- Platform -> Contracts
- UI -> Platform HTTP API
- CI integration -> CLI

**Forbidden**

- Core -> UI
- Core -> Platform
- Core -> Azure SDKs
- UI -> Core
- UI -> database
- Platform API -> source-code parser implementation
- external scanner adapter -> UI internals

## 8. Three end-to-end operating modes

### 8.1 Local developer mode

```text
Developer
   |
   v
CLI / IDE extension
   |
   v
AgentGuard Core
   |
   +--> local findings
   +--> local AI inventory
   +--> local AI-BOM
   +--> local HTML/SARIF/JSON
```

No SaaS dependency is required.

### 8.2 CI/CD mode

```text
Repository checkout
       |
       v
Pipeline adapter
       |
       v
AgentGuard CLI/Core
       |
       +--> pipeline policy decision
       +--> SARIF/JUnit/HTML artifacts
       +--> optional Platform upload
```

Two CI modes should be supported:

- **Offline gate:** results remain inside customer CI.
- **Connected gate:** normalized results are uploaded for central vulnerability management.

### 8.3 SaaS-managed scan

```text
User/UI or API
       |
       v
Platform creates Scan Job
       |
       v
Queue
       |
       v
Isolated Worker
       |
       +--> AgentGuard Core
       +--> External Engines
       |
       v
Normalized ScanResult
       |
       v
Platform ingestion
       |
       +--> Findings
       +--> Inventory / AI-BOM
       +--> Graph snapshot
       +--> Reports / metrics
```

## 9. Azure target deployment

A practical enterprise SaaS design is:

```text
Internet / Customer CI / IDE
            |
            v
Azure Front Door + WAF
            |
            v
Azure API Management
            |
            v
Microsoft Entra authentication
            |
            v
+------------------- AgentGuard control plane -------------------+
| Platform API | AuthZ | Projects | Findings | Admin | Reports   |
+---------------------------+-------------------------------------+
                            |
                            v
                    Azure Service Bus
                            |
           +----------------+----------------+
           |                                 |
           v                                 v
  AgentGuard scan worker            External engine worker
  ephemeral workspace               isolated adapter runtime
           |                                 |
           +----------------+----------------+
                            |
                            v
               normalized result ingestion
                            |
      +---------------------+---------------------+
      |                     |                     |
      v                     v                     v
Azure PostgreSQL       Blob Storage         Graph storage/index
metadata/lifecycle     artifacts/reports    graph snapshots

Supporting:
Key Vault, Managed Identities, ACR, Azure Monitor/App Insights,
Private Endpoints, Defender for Cloud, backup/recovery controls.
```

### 9.1 Hosting choice

For an initial enterprise SaaS release, use a small number of independently deployable services rather than dozens of microservices.

Recommended first deployment units:

1. `platform-api`
2. `scan-worker`
3. `web-ui`
4. optionally `graph-service` when graph workloads justify extraction

These can initially run on Azure Container Apps for operational simplicity or AKS if the team already has strong Kubernetes operations requirements. For customer-supplied/untrusted repository scanning, dedicated worker isolation is more important than whether the control plane uses AKS or Container Apps.

### 9.2 Tenant isolation

Isolation is a spectrum. Define service tiers:

- **Standard shared:** shared control plane, row-level tenant isolation, per-tenant encryption/context controls, isolated scan jobs.
- **Enhanced:** dedicated worker pool or node pool and optionally dedicated database/schema/storage boundary.
- **Dedicated enterprise:** deployment stamp with dedicated compute/data resources for one customer.

Untrusted customer code should not share a long-lived worker process across tenants.

## 10. Authentication and RBAC

Do not build an identity provider.

Use Microsoft Entra ID for workforce/enterprise identities and Microsoft Entra External ID/federation where customer identity requirements demand it.

Authorization belongs in the AgentGuard Platform because roles are product-specific.

Proposed roles:

- `PlatformOwner`
- `OrgAdmin`
- `SecurityAdmin`
- `SecurityAnalyst`
- `ProjectAdmin`
- `Developer`
- `Auditor`
- `IntegrationService`

Authorization scope hierarchy:

```text
Platform
  -> Organization/Tenant
      -> Workspace
          -> Project
              -> Scan / Finding / Inventory / Report
```

Every API request resolves:

```text
identity -> tenant -> role bindings -> resource -> action -> allow/deny
```

## 11. Canonical scan data model

### 11.1 Scan

A scan is an immutable observation.

Key fields:

- scan ID
- tenant/project
- source/ref/commit
- scanner engine versions
- rule-pack version
- start/end time
- state
- files scanned
- error/partial state

### 11.2 Finding

A Finding represents one logical security issue. An occurrence represents that finding in a specific scan.

Key fields:

- stable fingerprint
- engine ID
- rule ID
- title/description
- severity
- confidence
- CWE/OWASP/NIST mapping where applicable
- file/line/symbol
- evidence path
- source/sink for taint cases
- remediation
- lifecycle status

### 11.3 Inventory entity

Examples:

- agent
- sub-agent/orchestrator
- tool/function tool
- MCP server/client/tool/resource/prompt
- skill/plugin
- model/provider/embedding model
- vector store/retriever/RAG pipeline
- memory/checkpoint store
- prompt/guardrail
- API endpoint
- identity
- deployment

### 11.4 Relationship

Examples:

- `CALLS`
- `USES_TOOL`
- `CONNECTS_TO_MCP`
- `USES_MODEL`
- `READS_FROM`
- `WRITES_TO`
- `AUTHENTICATES_AS`
- `ROUTES_TO`
- `DEPENDS_ON`
- `CONTAINS`

Relationships must carry evidence and scan snapshot identity.

## 12. Vulnerability lifecycle architecture

The scanner returns detection facts. The platform adds lifecycle.

```text
Detected -> Open -> Triaged -> In Progress -> Resolved
                     |                         |
                     +-> Accepted Risk         +-> Reopened
                     +-> False Positive
                     +-> Suppressed (policy + expiry)
```

Rules:

- partial/failed scans must never automatically close earlier findings;
- a stable fingerprint must survive scan IDs;
- lifecycle events are append-only/auditable;
- suppressions require scope, actor, reason and optional expiry;
- SLA is calculated from policy, severity and project context.

## 13. AI inventory and AI-BOM architecture

The scanner owns discovery. The platform owns history and governance.

```text
Core inventory discovery
       |
       v
InventoryEntity + Relationship contracts
       |
       +--> local AI-BOM exporter
       |
       v
Platform inventory history
       |
       +--> ownership / approval flags
       +--> version history
       +--> CycloneDX export
       +--> policy evaluation
```

Do not make AI-BOM generation dependent on the UI.

## 14. Provenance and attack-path architecture

The current provenance relationships are a useful seed, but enterprise graph design should separate raw facts from derived security paths.

```text
RAW GRAPH
Agent -> MCP -> Tool -> API -> Data store
  |                         ^
  +-> Model                 |
  +-> Identity -------------+

SECURITY OVERLAY
Finding -> vulnerable node/edge
Credential -> identity edge
Privilege -> capability edge
Data classification -> data node
```

Derived queries include:

- Can an externally influenced prompt reach a privileged tool?
- Which agents can reach production data?
- Which identities are shared across multiple high-risk agents?
- What is the blast radius of a compromised MCP server?
- Which high-severity finding participates in the largest reachable path?

The graph service is optional in the first refactor. Define the contract first; extract the service when graph processing becomes independently scalable.

## 15. Dashboard architecture

The dashboard should be configurable using saved widget definitions rather than hard-coded screens.

Example widget model:

```json
{
  "type": "severity_trend",
  "title": "New High/Critical",
  "scope": {"projects": ["payments-ai"]},
  "filters": {"status": ["open"]},
  "visualization": "line",
  "time_window": "90d"
}
```

Supported widgets can include:

- severity distribution;
- new vs resolved trend;
- findings by agent/MCP/tool;
- top vulnerable projects;
- policy gate failures;
- AI inventory type count;
- unsupported/unapproved models;
- exposed MCP endpoints;
- risk by graph reachability;
- SLA breaches;
- scan health and coverage.

## 16. Reporting architecture

Use one canonical report data model and multiple renderers.

```text
Platform/local ScanResult
       |
       v
Report Model
       |
       +--> JSON
       +--> SARIF
       +--> CSV/XLSX
       +--> JUnit
       +--> HTML
       +--> PDF
       +--> CycloneDX
```

HTML reports should be self-contained for offline sharing, with sections that can be enabled/disabled per template.

## 17. Recommended monorepo structure

Keep one repository initially. Separate packages and deployables, not teams into separate repositories.

```text
AgentGuard/
|
+-- packages/
|   +-- contracts/
|   +-- core/
|   +-- cli/
|   +-- reporting/
|   +-- aibom/
|   +-- plugin-sdk/
|
+-- integrations/
|   +-- github-actions/
|   +-- azure-devops/
|   +-- jenkins/
|   +-- gitlab/
|   +-- skillspector/
|   +-- cisco-ai-defense/
|
+-- services/
|   +-- platform-api/
|   +-- scan-worker/
|   +-- graph-service/       # extract when needed
|   +-- report-worker/       # optional later
|
+-- apps/
|   +-- web/
|
+-- deploy/
|   +-- azure/
|
+-- docs/
|   +-- architecture/
|   +-- api/
|   +-- adr/
|   +-- security/
|   +-- development/
|
+-- tests/
    +-- golden-repositories/
    +-- contracts/
    +-- integration/
    +-- e2e/
```

## 18. Software artifacts produced by each layer

- **Contracts:** versioned Python package plus JSON Schema; consumed everywhere.
- **Core:** Python wheel/library; runs on developer machines, CI and scan workers.
- **CLI:** Python wheel plus optional standalone binary; runs on developer machines and CI.
- **CI adapters:** marketplace action/plugin/templates; run inside pipeline systems.
- **Platform API:** container image; runs in Azure.
- **Scan worker:** hardened container image; runs in Azure or a customer-hosted worker environment.
- **UI:** web container/static bundle; runs in Azure.
- **Graph service:** container image only if graph processing is extracted.
- **Report worker:** container image only if asynchronous report rendering is required.

## 19. Team ownership

A small team can work without stepping on each other by assigning boundaries:

- **Scanner team:** Core, rules, analyzers, inventory discovery.
- **Platform team:** API, tenants, RBAC, scans, lifecycle, database.
- **Frontend team:** Web UI and graph visualization.
- **Integration team:** CI, SCM, third-party engines, tickets.
- **Security/platform engineering:** worker sandbox, Azure IaC, identity, logging, secrets.

Shared changes to Contracts require architecture review because they affect multiple components.

## 20. Migration plan that does not change scanner behavior

### Phase 0 - Freeze behavior

- build golden test repositories;
- capture existing finding fingerprints/results;
- record inventory and AI-BOM fixtures;
- add contract regression tests.

### Phase 1 - Extract contracts

- define `ScanRequest`, `ScanResult`, `Finding`, `Entity`, `Relationship`;
- adapt current scanner output to those contracts;
- keep existing Store compatibility temporarily.

### Phase 2 - Separate Core and CLI packaging

- move scanner/analyzers/rules to `packages/core`;
- move Typer commands to `packages/cli`;
- remove FastAPI/Jinja dependencies from Core installation;
- ensure local scans still produce identical findings.

### Phase 3 - Reporting and CI

- extract format renderers;
- add deterministic exit-policy engine;
- ship GitHub/Jenkins/Azure DevOps examples/adapters.

### Phase 4 - Platform foundation

- PostgreSQL;
- tenant/project model;
- Entra authentication;
- application RBAC;
- scan ingestion API;
- vulnerability lifecycle;
- audit events.

### Phase 5 - Asynchronous SaaS scans

- queue;
- isolated worker;
- source snapshot/artifact model;
- worker resource/egress sandbox;
- scan upload and normalized ingestion.

### Phase 6 - New UI

- independent web app consuming Platform API;
- customizable dashboard;
- finding/project/scan workflow;
- administration and integration screens.

### Phase 7 - Graph and ecosystem expansion

- graph snapshot service/index;
- attack-path queries;
- generic plugin SDK;
- Cisco/other engines;
- enterprise reports and integrations.

## 21. Architecture quality gates

The architecture is considered correctly separated when all of these are true:

- `agentguard-core` can install without FastAPI, React, Azure, database server or identity dependencies;
- a developer can scan a repository offline;
- a pipeline can run the same scanner and get deterministic exit codes;
- UI has no database credentials and no import path to Core;
- Platform API can ingest a result produced outside the SaaS environment;
- workers can be replaced without changing Platform APIs;
- external engines normalize to the same contracts;
- all tenant-scoped database reads/writes require tenant context;
- graph UI renders a graph contract rather than reading scanner internals;
- upgrading UI does not require upgrading Core in lockstep.

## 22. Decisions recommended now

1. **Keep a monorepo.** Separate packages/deployables first.
2. **Preserve Core behavior.** Refactor boundaries before detection logic.
3. **Make Contracts versioned.** Treat them like an API.
4. **Support offline and connected modes.** Do not require SaaS for scanning.
5. **Use asynchronous workers for SaaS scans.** Never scan customer code in API pods.
6. **Use Entra for authentication.** Product authorization remains AgentGuard's responsibility.
7. **Use PostgreSQL for SaaS metadata/lifecycle.** Keep SQLite only for local mode.
8. **Treat untrusted repository scanning as a sandbox problem.** Default-deny egress and ephemeral workspaces.
9. **Keep graph as a domain boundary.** Do not prematurely split it into a separate service.
10. **Use a plugin SDK for third-party engines.** UI must not special-case every vendor.

## 23. What to build first

The first code change should not be Azure or React. It should be:

```text
Current Scanner -> stable ScanResult contract -> regression tests
```

Once that exists, Core/CLI/CI/Platform/UI separation becomes controlled instead of risky.

## 24. References used for architecture comparison

- AgentGuard repository README and current enterprise architecture documentation, reviewed 2 September 2026.
- Snyk documentation: CLI, IDE and CI/CD integrations; CI/CD integration guidance.
- Semgrep documentation: local CLI scans and AppSec Platform upload workflows.
- Checkmarx One documentation: standalone CLI and plugin backbone behavior.
- Microsoft Azure Architecture Center: multitenant AKS, API Management, identity and tenancy models.
