# Team Development Guide

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
