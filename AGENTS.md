# AgentGuard — Codex Repository Instructions

## Purpose

AgentGuard is a static security scanner for AI/agentic applications. It scans source code, agent definitions, MCP components, tools, skills, prompts, model integrations, data/retrieval components, and related configuration. The product is intended to evolve into an enterprise multi-client platform, but this repository is currently focused on the reusable scanner Core, local CLI, and CI/CD integration.

## Required reading before substantial changes

Read these files before making architectural or scanner changes:

1. `docs/CODEX_PROJECT_CONTEXT.md` — authoritative handoff from the prior development session.
2. `docs/CODEX_NEXT_WORK.md` — current implementation priorities and known gaps.
3. `docs/ARCHITECTURE_AND_PACKAGING.md` — package boundaries.
4. `docs/RULE_CATALOG_IMPLEMENTATION.md` and `RULE_COVERAGE.json` — rule catalog and detector depth.
5. `docs/SKILL_SECURITY_ENGINE.md` and `docs/SKILLSPECTOR_UPSTREAM_RECONCILIATION.md` — internal skill security implementation and upstream parity policy.
6. `docs/AI_AGENT_BOM_V2.md` — inventory/BOM/version identity contract.
7. `docs/PROVENANCE_GRAPH_DATA_CONTRACT.md` and `docs/PROVENANCE_UI_ARCHITECT_HANDOFF.md` — graph contract and UI handoff.
8. `BUILD_VALIDATION.md` — last validated state.

## Architecture invariants

Use this separation strictly:

`Core scans -> CLI/CI invoke Core -> future Platform manages enterprise state -> future UI consumes Platform APIs.`

### Core owns

- static analysis and parsing
- interprocedural/taint analysis
- rule evaluation
- skill security analysis
- AI inventory discovery
- AI/Agent BOM generation
- provenance graph construction
- finding evidence/enrichment
- report/export data contracts

### Core must NOT own

- authentication or user sessions
- SaaS tenancy
- database/platform persistence
- web UI
- cloud-specific account state
- GitHub-specific workflow behavior

The future FastAPI/platform worker must import `agentguard_core`; it must not shell out to the CLI.

## Rule catalog is a protected product asset

The bundled source-of-truth currently contains 181 catalog rules:

- 113 AgentGuard/native rules
- 68 SkillSpector-origin compatibility rules mapped into AgentGuard `NVS-*` identities

Never delete, silently rename, or omit catalog rules to make tests pass. If a rule cannot yet be executed deeply, preserve the rule and accurately mark detector depth/status in `RULE_COVERAGE.json` and documentation.

Distinguish clearly between:

- catalog coverage: rule exists and is valid
- detector coverage: executable deterministic/semantic/network detector exists
- deep analysis: taint/interprocedural/control-flow semantics are implemented

Do not claim all 181 rules are equally mature.

## SkillSpector policy

AgentGuard should not require the NVIDIA SkillSpector executable at runtime. Skill security behavior relevant to the AgentGuard catalog is implemented inside Core.

The current AgentGuard compatibility baseline is the 68 `NVS-*` rules in the user's risk catalog. Upstream SkillSpector evolves independently, so reconcile upstream changes intentionally; do not silently mutate stable AgentGuard rule IDs.

If behavior or source code is directly copied from Apache-2.0 upstream projects, preserve required copyright/license/NOTICE obligations and update `THIRD_PARTY_NOTICES.md`. Prefer independent implementation of concepts when practical.

## Finding contract

Findings must remain rich enough for CLI, CI, reports, graph, and future SaaS use. Preserve at least:

- stable finding ID/fingerprint
- rule ID/title/category/severity
- description and remediation
- source/sink/detection logic when applicable
- evidence/code/file/line
- confidence/analysis type
- mappings/references/CWE when known

Detection and enrichment should remain separated when possible: analyzers detect; rule metadata enriches.

## AI inventory and version identity

Never use a content hash or framework package version as a substitute for the logical agent/application version.

Keep these concepts separate:

- `entity_id`: stable logical identity for the asset
- `version_id`: identity of one asset version/revision
- `version`: human/project version value when discoverable
- `version_source` and `version_scheme`
- `framework` and `framework_version`
- `package_name` and `package_version`
- Git repository/commit/tag/branch when available
- `content_hash`: integrity/revision digest only

Agent BOM must expose agents explicitly and their dependencies/relationships, not only generic components.

## Provenance graph contract

The scanner, not the UI, is responsible for returning structured graph data. Preserve first-class:

- asset nodes: repository, agent/sub-agent/orchestrator, model, tool, skill, MCP server/client/tool/resource/prompt, memory, retriever/vector store, guardrail, etc.
- typed relationship edges with code evidence
- finding nodes linked to affected assets
- source/propagator/sink evidence nodes where applicable
- attack paths with ordered node/edge IDs
- per-node risk summaries and version identity

The future UI should be able to render the graph without reverse engineering analyzer internals.

## Development priority

Scanner correctness has priority over SaaS/platform features. The current main work is to deepen rules that are present in the catalog but still require dedicated semantic/control-flow detectors, and to add vulnerable + safe regression fixtures for every meaningful detector.

Do not spend effort on authentication, SaaS persistence, Azure deployment, or a production web UI unless explicitly requested.

## Testing rules

For every new or materially changed detector, add both:

1. a vulnerable/positive fixture that must trigger; and
2. a safe/negative fixture that must not trigger.

Where taint is expected, test source -> propagation -> sink evidence, not merely the final sink match.

Before declaring a change complete, run at minimum:

```bash
pytest -q
python -m compileall packages/core/src packages/cli/src
```

Also validate the rule catalog through the CLI when the package/environment is available:

```bash
agentguard rules validate
```

The expected catalog count for this handoff is 181 unless the catalog has been deliberately versioned and documented.

## Packaging

There are two Python distributions:

- `agentguard-core`: reusable scanner engine/SDK
- `agentguard-cli`: developer-facing command that depends on Core

Normal end users should eventually install only `agentguard-cli`; pip/pipx/uv resolves the Core dependency. CI/CD must use the same CLI/Core engine, not a separate scanner implementation.

## Git and user workflow

The user wants to test locally before committing changes. Do NOT create commits, push branches, open pull requests, or modify the remote GitHub repository unless the user explicitly asks for that action.

Prefer Windows PowerShell-compatible local instructions because the user primarily develops on Windows. Docker is not the preferred local path for this project unless explicitly requested.

## Change discipline

- Preserve backward-compatible contracts unless a versioned migration is intentional.
- Do not replace deep AST/taint logic with regex-only shortcuts.
- Do not report a detector as implemented simply because a YAML rule exists.
- Avoid duplicate findings when multiple analyzers identify the same semantic issue; preserve the best evidence.
- Keep paths repository-relative in portable outputs.
- Make outputs deterministic where practical.
- Record important architecture/rule-contract changes in `docs/CODEX_PROJECT_CONTEXT.md` or an appropriate durable design document so the next Codex session can recover context from the repository.
