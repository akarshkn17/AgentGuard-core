# AgentGuard Core + CLI + GitHub Actions Adapter — v0.4.0

AgentGuard is structured as a reusable **scanner core** with thin adapters for developer CLI and CI/CD use. The same `ScanResult` contract is intended to power a future API/SaaS worker without duplicating scanner logic.

> **Design rule:** Core scans. CLI/CI invoke Core. Future services import Core.

## What changed in v0.4.0

### Bounded Python code intelligence

Core builds one in-memory Python code-intelligence session per scan. It indexes modules, classes, functions, methods, nested functions, parameters, decorators and source ranges; records call-resolution confidence; and supports bounded cross-file, method, attribute, container, argument/parameter and return-value taint propagation.

Sanitizers are classified as `proven`, `partial`, `unverified` or `absent`. A function named `validate_*` or `sanitize_*` no longer clears taint without a configured contract or conservative structural proof. See `docs/CODE_INTELLIGENCE_MILESTONE_1.md`.

### Complete supplied risk catalog

The bundled catalog is generated from `docs/source/AgentGuard_Risk_Catalog_with_Controls.xlsx` and contains **181 rules**:

- **113 AgentGuard native rules**
- **68 SkillSpector-origin compatibility rules** (`NVS-*`) executed by AgentGuard's internal skill-security engine

Run:

```bash
agentguard rules validate
agentguard rules list
```

`RULE_COVERAGE.json` records implementation depth per rule. Catalog presence and detector precision are intentionally tracked separately: all 181 rules are bundled, while deeper semantic/control-flow work is still identified explicitly for native rules that are not yet deep-flow detectors.

### Native skill-security analysis

The 68 `NVS-*` rules in the supplied catalog no longer require the NVIDIA SkillSpector executable. `agentguard_core.skill_analyzer.SkillSecurityAnalyzer` performs local static checks for prompt/instruction attacks, permission/capability mismatch, supply-chain issues, AST execution patterns, lightweight taint, trigger/metadata poisoning, Unicode deception, and malware-like indicators.

Two supply-chain checks need live data:

- `NVS-SC4` — OSV vulnerability lookup
- `NVS-SC5` — package-maintenance lookup

They run only with `--network-enrichment`; default scanning remains offline.

### AI inventory and version identity fixed

AgentGuard no longer treats a content digest or framework version as if it were the agent's business/application version.

Each asset now separates:

- `entity_id` — stable logical identity across scans/versions
- `version_id` — stable identity for a particular observed version/revision
- `version` — human-readable version when determinable
- `version_source` / `version_scheme` — how that version was resolved
- `framework_version` — e.g. LangGraph package version
- `package_version` — package dependency version when applicable
- `content_hash` — immutable content revision evidence
- Git commit/branch/tag/remote evidence

Version resolution favors explicit agent/skill manifests and Agent Cards, then project manifests, Git tags/commits, and finally content revision evidence. It does not invent semantic versions.

### Rich Agent BOM and AI BOM

Outputs include:

- **CycloneDX 1.7 AI/ML BOM** — `agentguard-aibom.cdx.json`
- **AgentGuard Agent BOM v2** — `agentguard-agent-bom.json`

Agent BOM v2 includes agents, agent-version IDs, models, tools, MCP components, skills, capabilities, dependencies, relationships and version evidence.

### Provenance/security graph contract

AgentGuard now exports a UI-oriented graph payload:

```bash
agentguard graph . -o agentguard-provenance.json
# or
agentguard scan . --format graph
```

The graph contains:

- typed asset nodes: agent, sub-agent, tool, model, MCP, skill, memory, retriever, data store, dependency, capability, etc.;
- typed relationship edges with file/line evidence;
- finding nodes with severity/remediation;
- expandable evidence nodes for source → propagator → sink/static evidence;
- per-asset risk summaries;
- version identity on each asset;
- `attack_paths[]` for UI focus/highlight mode.

See `docs/PROVENANCE_GRAPH_DATA_CONTRACT.md` and `docs/samples/agentguard-provenance.sample.json`.

## Repository layout

```text
AgentGuard-Core-CLI-CICD-v0.4.0/
├─ packages/
│  ├─ core/                 # scanner engines, rules, inventory, BOM, graph contracts
│  └─ cli/                  # local/CI adapter; no authentication
├─ integrations/github/     # GitHub Actions adapter/examples
├─ examples/
│  ├─ vulnerable_agent/
│  ├─ vulnerable_skill/
│  └─ multi_agent_demo/
├─ tests/
├─ scripts/
├─ RULE_COVERAGE.json
└─ docs/
   ├─ RULE_CATALOG_IMPLEMENTATION.md
   ├─ SKILL_SECURITY_ENGINE.md
   ├─ AI_AGENT_BOM_V2.md
   ├─ PROVENANCE_GRAPH_DATA_CONTRACT.md
   ├─ schemas/provenance-graph.schema.json
   ├─ samples/
   └─ source/AgentGuard_Risk_Catalog_with_Controls.xlsx
```

## Install from source on Windows

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .\packages\core
python -m pip install -e .\packages\cli

agentguard version
agentguard rules validate
```

## Scan

```powershell
agentguard scan C:\path\to\project --verbose --fail-on none
```

Generate all major artifacts:

```powershell
agentguard scan . `
  --output-dir .\agentguard-results `
  --format json `
  --format findings-json `
  --format sarif `
  --format csv `
  --format junit `
  --format html `
  --format html-summary `
  --format markdown `
  --format aibom `
  --format agent-bom `
  --format graph `
  --fail-on none
```

Optional live enrichment:

```powershell
agentguard scan . --network-enrichment
```

## Inventory / BOM / graph commands

```powershell
agentguard inventory . -o inventory.json
agentguard bom . --kind aibom -o agentguard-aibom.cdx.json
agentguard bom . --kind agent-bom -o agentguard-agent-bom.json
agentguard graph . -o agentguard-provenance.json
```

## Use Core as an SDK

```python
from pathlib import Path
from agentguard_core import ScanRequest, scan, generate_agent_bom, generate_provenance_graph

result = scan(ScanRequest(Path("./application")))

for finding in result.findings:
    print(finding.finding_id, finding.rule_id, finding.description)

agent_bom = generate_agent_bom(result)
graph = generate_provenance_graph(result)
```

Future FastAPI workers should import `agentguard-core` directly rather than execute the CLI using `subprocess`.

## Install the wheels

Build:

```powershell
.\scripts\build-wheels.ps1
```

Install locally:

```powershell
python -m pip install .\dist\agentguard_core-0.4.0-py3-none-any.whl
python -m pip install .\dist\agentguard_cli-0.4.0-py3-none-any.whl
```

For normal customer distribution, publish Core first and CLI second to PyPI or a private Python registry. Developers normally install only `agentguard-cli`; its package dependency installs the matching Core automatically.

## CI severity gate

```bash
agentguard scan . --fail-on high
```

The process exits non-zero when a finding meets or exceeds the configured threshold.

## Authentication boundary

There is intentionally no authentication for local scanning. Future SaaS authentication belongs in the CLI/API adapters, not scanner Core. See `docs/AUTH_FUTURE.md`.

## Important precision note

**All 181 rules from the supplied catalog are present.** That does not mean every rule has identical analysis depth. `RULE_COVERAGE.json` and `docs/RULE_CATALOG_IMPLEMENTATION.md` distinguish deep-flow, structural/config, semantic/control-flow enhancement, native skill-static, behavior-mismatch and network-conditional detectors. This is intentional so the product does not overstate scanner coverage.

## Continue development with Codex

This repository contains persistent Codex project context. Start with `CODEX_START_HERE.md`; Codex should automatically load the root `AGENTS.md` instructions when opened from the repository root.
