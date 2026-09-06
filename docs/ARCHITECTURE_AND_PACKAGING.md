# AgentGuard Core, CLI and CI/CD Packaging

## Decision

AgentGuard is split into two distributable Python packages and one CI adapter:

```text
Customer repository
     │
     ├── Developer shell ───────────────┐
     │                                  │
     └── GitHub Actions ────────────────┤
                                        ▼
                               agentguard-cli
                              (adapter / UX / policy)
                                        │
                                        ▼
                               agentguard-core
                   (scan engines + findings + inventory + BOM)
                                        │
             ┌──────────────────────────┼──────────────────────────┐
             ▼                          ▼                          ▼
      Python AST/dataflow        Tree-sitter/config        AI inventory/BOM
```

`agentguard-core` must never depend on authentication, FastAPI, a database, a web UI, GitHub Actions, or a cloud SDK. That is what makes the scanner reusable in local development, CI workers, future SaaS workers, and a future Python SDK.

## Package 1: `agentguard-core`

Use it as a Python library:

```python
from pathlib import Path
from agentguard_core import ScanRequest, scan

result = scan(ScanRequest(Path("my-repo")))
for finding in result.findings:
    print(finding.finding_id, finding.rule_id, finding.description)
```

Core returns the versioned `ScanResult` contract. It does not write a database and does not require a login.

## Package 2: `agentguard-cli`

The CLI is deliberately thin. It:

- parses commands and flags;
- calls Core;
- prints table/verbose terminal output;
- applies the CI severity exit-code gate;
- writes reports in JSON, SARIF, CSV, JUnit XML, Markdown, detailed HTML, summary HTML, CycloneDX AI BOM, and Agent BOM formats.

The CLI does not reimplement scanning rules.

## Package 3: GitHub Actions adapter

`integrations/github/` contains:

- `action.yml` for the future published package;
- `example-local-workflow.yml` for testing before publishing;
- `example-published-workflow.yml` for normal customer/team consumption.

GitHub Actions consumes exactly the same `agentguard` CLI as a developer laptop. This avoids a second scanner implementation in CI.

## Artifact and publication model

### Internal testing

Build wheels:

```powershell
.\scripts\build-wheels.ps1
```

Then hand another team the two files under `dist/`. They install both:

```powershell
python -m pip install .\agentguard_core-0.4.0-py3-none-any.whl .\agentguard_cli-0.4.0-py3-none-any.whl
agentguard version
```

### Package registry

Publish **Core first**, then CLI. The CLI pins the matching Core minor release. Suitable registries include public PyPI or a private Python registry such as Azure Artifacts, GitHub Packages-compatible package infrastructure, Artifactory, or Nexus.

End users should normally install only the CLI:

```bash
pipx install agentguard-cli==0.4.0
# or
uv tool install agentguard-cli==0.4.0
```

Python/automation developers who want direct SDK access install `agentguard-core`.

## Versioning

Use three related but distinct versions:

1. **Core package version** — SemVer, e.g. `0.4.0`.
2. **CLI package version** — normally released with the compatible Core version.
3. **Scan contract version** — currently `1.2`; change only when the serialized result contract changes.

A new rule can usually be a patch release. A new optional output format can usually be a minor release. Breaking Python APIs or finding/scan contracts require a major-version decision.

## Future FastAPI/SaaS

Do not expose the CLI process through HTTP. A future worker/API package should import `agentguard-core` directly:

```text
FastAPI/API -> job queue -> isolated scan worker -> agentguard-core -> ScanResult
```

The platform stores and manages the returned contract; Core remains unaware of tenants, users and databases.
