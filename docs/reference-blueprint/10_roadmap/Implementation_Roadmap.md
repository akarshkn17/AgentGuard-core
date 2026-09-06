# Implementation Roadmap

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
