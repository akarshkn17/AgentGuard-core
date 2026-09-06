# Migration from AgentGuard 0.2 Prototype

## Preserved

- Python project-wide AST/index and interprocedural source-to-sink analysis approach.
- Structural checks such as `shell=True`, `verify=False`, `trust_remote_code=True`, unsafe deserialization and YAML loading.
- JS/TS tree-sitter adapter boundary.
- Configuration/skill scanning approach.
- Rule YAML model and rule IDs.
- Semantic finding fingerprint algorithm.
- AI inventory structural discovery concepts and relationships.

## Moved out of Core

The old prototype mixed these concerns into one distribution. They are intentionally not dependencies of `agentguard-core` now:

- SQLite persistence and registry state;
- FastAPI/Uvicorn;
- UI/static assets;
- user/RBAC/tenant state;
- external scanner process adapters;
- cloud deployment concerns.

They can consume the Core contract later.

## New in Core/CLI

- versioned `ScanResult` contract;
- repository-relative finding/evidence paths;
- stable `finding_id` in addition to the existing fingerprint;
- rule-driven description and remediation on every normalized native finding;
- inventory categories and explicit version provenance;
- CycloneDX AI BOM and Agent BOM from the in-memory result;
- detailed and summary HTML reports without requiring SQLite;
- JSON/SARIF/CSV/JUnit/Markdown exports;
- severity-based CLI exit policy;
- GitHub Actions adapter examples.

## Intentionally deferred

- provenance/attack-path graph visualization and richer graph inference;
- SaaS REST/FastAPI layer;
- authentication and tenant authorization;
- centralized vulnerability lifecycle/database;
- authenticated result upload.
