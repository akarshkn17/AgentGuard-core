# AgentGuard Codex Project Context

## Why this file exists

This is the durable handoff from the ChatGPT development sessions into local Codex development. Treat it as project context, not as executable requirements where it conflicts with current source/tests. Update it when major architectural decisions change.

## Product goal

AgentGuard is intended to become a scalable static security scanner and later an enterprise platform for AI/agentic applications. It should scan ordinary application code plus agents, sub-agents/orchestrators, MCP servers/clients/tools/resources/prompts, skills, tools/plugins, prompts, model integrations, memory, retrieval/RAG components, vector stores, data stores, guardrails, and related configuration.

The immediate priority is scanner quality and reusable local/CI packaging. SaaS/platform work is later.

## Current packaging

Version at this handoff: `0.4.0`.

Two wheels are built:

- `agentguard_core-0.4.0-py3-none-any.whl`
- `agentguard_cli-0.4.0-py3-none-any.whl`

Core is the reusable engine. CLI is a thin adapter and should eventually be what developers install directly with pipx/uv/pip.

## Architecture decision

The governing architecture is:

`Core scans. CLI/CI invoke Core. Platform manages enterprise state. UI consumes Platform APIs.`

Core owns analysis, rules, taint, inventory, evidence, BOM, provenance and scanner contracts. Core must not depend on SaaS authentication, tenant state, a database, UI, or cloud platform services.

Future FastAPI/workers should import the Core Python API directly rather than invoke the CLI as a subprocess.

## Risk/rule catalog

The user maintains `AgentGuard_Risk_Catalog_with_Controls.xlsx` as a product-level risk/rule catalog for the scanner.

At the v0.4 handoff:

- 181 rules load and validate.
- 113 are AgentGuard/native catalog rules.
- 68 are SkillSpector-origin compatibility rules mapped into stable AgentGuard `NVS-*` identities.

`RULE_COVERAGE.json` is the auditable implementation-depth manifest. The last classified state was:

- 44 deep flow/taint capable
- 34 structural/config capable
- 64 native skill static
- 2 skill behavior/description mismatch
- 2 skill network-dependent supply-chain checks
- 35 native semantic/control-flow rules needing deeper dedicated implementation

Those numbers are a status snapshot, not a permanent target. Keep the manifest synchronized with reality.

The key policy is that catalog presence must never be confused with detector maturity.

## SkillSpector history and current direction

Earlier AgentGuard versions called NVIDIA SkillSpector as an external scanner/tool. The user explicitly requested that the relevant SkillSpector security-analysis behavior be implemented inside AgentGuard instead.

v0.4 introduces a native `skill_analyzer.py` and converts the 68 catalog-mapped SkillSpector-origin rules to AgentGuard-native skill analysis. AgentGuard should not require a SkillSpector executable at runtime.

Upstream SkillSpector continues to evolve and has more/newer patterns and analyzers than the user's 68-rule baseline. The stable AgentGuard catalog should therefore be treated as a compatibility contract; upstream deltas should be reviewed and deliberately imported/versioned instead of silently changing IDs or behavior.

Current upstream concepts worth reconciling over time include prompt injection, anti-refusal, exfiltration, privilege escalation, supply chain, excessive agency, output handling, prompt leakage, memory poisoning, tool misuse, rogue/persistence, trigger abuse, behavioral AST, behavioral taint, YARA/artifact analysis, MCP least privilege, MCP tool poisoning, SSRF, and insecure deserialization.

Two checks such as known vulnerable dependencies / abandoned dependencies inherently benefit from current external advisory/package data. Offline core scanning should stay functional; network enrichment should be explicit.

## Existing Core analysis approach

The Python project analyzer is intended to be more than regex matching. Existing design includes project-wide AST/interprocedural analysis, import/local function resolution, propagation through assignments and function parameters/returns, sources such as LLM outputs/retrieval/MCP/tool inputs, and sinks such as shell/dynamic execution/SQL/network/file operations.

Configuration and skill scanners cover structural risks. Optional tree-sitter analysis extends structural coverage to JS/TS.

Do not regress deep rules into superficial text matching.

## Milestone 1 code-intelligence foundation (September 6, 2026)

Milestone 1 introduced `agentguard_core.code_intelligence` and retained the existing public scanner contracts. A per-scan `CodeIntelligenceSession` now owns the Python symbol index, resolver, call graph structures, bounded analysis limits and data-flow edges. The index covers modules, classes, functions, methods, nested functions, parameters, decorators and source ranges. Scanner Python analysis and inventory share this index.

The project analyzer now uses abstract locations for locals, attributes, container keys/indices and returns. It supports bounded receiver aliases, method calls, imported aliases, cross-file/nested calls, argument-to-parameter propagation and return-value propagation. Call resolution records confidence and derivation instead of silently treating every match as exact.

The previous name-only sanitizer clearing behavior was removed. Sanitizer results are `proven`, `partial`, `unverified` or `absent`; only a sink-appropriate built-in contract or conservative structural allowlist proof clears applicable taint. Partial/unverified sanitizer evidence remains visible.

The validated suite now contains 18 tests: the original 6 plus 12 code-intelligence tests with durable vulnerable, safe and edge fixtures. Representative finding IDs remained identical to the pre-refactor v0.4.0 wheel. See `docs/CODE_INTELLIGENCE_MILESTONE_1.md`.

## Finding enrichment

Detection and metadata enrichment are separated. An analyzer can emit a rule ID/evidence, after which the rule catalog enriches it with description, remediation, category, source/sink descriptions, detection logic, references, mappings and CWE metadata.

Reports and future UI must show actionable description/remediation, not only `rule_id + line`.

## AI inventory / AI BOM / Agent BOM issue that was corrected

The previous implementation produced too little agent-specific data and conflated version concepts. v0.4 changes the model so identity/version/integrity metadata are distinct.

Required concepts:

- stable logical `entity_id`
- per-version/revision `version_id`
- explicit `version` value when discoverable
- `version_source` and `version_scheme`
- framework name/version
- package name/version
- Git commit/tag/branch when known
- content digest only for integrity/revision evidence

Do not label a SHA/content hash as the human agent version. Do not label `langgraph==X` as the agent version.

The normalized AI inventory taxonomy includes at least:

- agentic: agent, sub-agent, orchestrator, agent proxy
- tooling: tool, function tool, skill, plugin
- MCP: server, client, gateway, tool, resource, prompt
- model runtime: model, embedding, LLM endpoint, model endpoint
- data/retrieval: vector store, retriever, dataset, knowledge base, feature store, RAG pipeline
- memory/state
- prompting
- safety/guardrails
- operations/dependencies/capabilities

Agent BOM v2 is AgentGuard-specific and should explicitly group agents, agent versions, dependencies, assets, and relationships. CycloneDX AI BOM remains useful for interoperability.

## Provenance graph

The user needs the scanner to produce data rich enough for a separate UI/UX designer and architect to build an interactive provenance/attack-path experience.

The scanner must return a structured graph contract; the UI should not infer graph semantics from arbitrary finding strings.

Graph output includes:

- typed asset nodes
- typed relationship edges
- evidence attached to edges (file/line/symbol/resolution when known)
- finding nodes linked to affected assets
- evidence nodes for source/propagation/sink flows
- precomputed `attack_paths[]`
- risk summaries and version identity on assets

Typical relationships include `DEFINES`, `USES_MODEL`, `USES_TOOL`, `USES_SKILL`, `USES_MEMORY`, `USES_RETRIEVER`, `USES_MCP_SERVER`, `USES_GUARDRAIL`, `CONTAINS_NODE`, `EXPOSES_TOOL`, `EXPOSES_RESOURCE`, `EXPOSES_PROMPT`, `HAS_CAPABILITY`, `HAS_FINDING`, and `HAS_EVIDENCE`.

The UI should be able to select an attack path and simply highlight ordered node/edge IDs returned by Core.

## Reference repositories considered

The project previously reviewed concepts from:

- user repository: `akarshkn17/AgentGuard`
- NVIDIA SkillSpector
- Cisco AI Defense AI BOM
- `msaad00/agent-bom`

External projects are design/reference inputs unless explicitly integrated. Avoid runtime dependencies merely for conceptual reuse. `THIRD_PARTY_NOTICES.md` documents licensing considerations.

## Current validation snapshot

At the Milestone 1 validation gate the source suite reported 18 passing tests. Catalog validation still reported 181 valid rules. A representative multi-agent fixture retained its finding IDs and produced findings, AI assets/relationships, Agent BOM/AI BOM, and a provenance graph with finding-linked attack paths. See `BUILD_VALIDATION.md` for the exact recorded run.

## User workflow constraints

The user develops primarily on Windows/PowerShell. They want to test locally before committing changes to GitHub. Docker was previously troublesome and is not the preferred development path.

Do not perform GitHub write operations or commits without explicit user instruction.

## Product direction after Core quality

Likely later layers include:

- GitHub/GitLab/Azure DevOps CI adapters
- FastAPI scanner/platform services
- authentication/RBAC/tenancy
- enterprise persistence/version history
- interactive graph UI
- integrations with external scanners
- SaaS deployment (Azure was previously preferred)

But these should not distract from current scanner correctness unless the user changes priorities.
