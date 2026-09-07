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

## Milestone 2 evidence-backed provenance (September 6, 2026)

Milestone 2 reuses the Milestone 1 `CodeIntelligenceSession` to construct explicit asset, code, security and supply-chain graph nodes. Relationships now carry a relationship nature (`explicit/direct`, `inferred`, or `transitive/derived`), confidence, derivation method and source evidence.

Code findings are attributed through ordered finding evidence, containing symbols, explicit implementation ownership, reverse call edges and upstream inventory relationships. The most specific owners are stored in `directly_affected_assets`; upstream agents/orchestrators are stored separately in `transitively_affected_assets`. Exact declared-file ownership handles non-code assets where available, with repository ownership as the final explicit fallback. Nearest-line proximity is no longer the primary ownership mechanism.

Attack paths are connected traversals over emitted graph edges and retain the full source/propagator/sink evidence order. Durable vulnerable, safe and inferred cross-file fixtures, golden semantic graph projections and Draft 2020-12 schema validation are in `tests/fixtures/provenance/`, `tests/golden/` and `tests/test_provenance.py`.

At the Milestone 2 gate, public identifiers remained `ScanResult 1.2`, provenance graph `1.0`, Agent BOM `2.0`, and CycloneDX 1.7. See `docs/PROVENANCE_MILESTONE_2.md`.

## Milestone 3 Agent BOM, model, package, and vulnerability foundation (September 6, 2026)

Milestone 3 adds first-class `ModelEntity`, `PackageEntity`, and `VulnerabilityRecord` collections to the additive `ScanResult 1.2` contract. Model discovery normalizes LangChain/LangGraph wrappers, OpenAI/Azure OpenAI, Anthropic, Bedrock, Google Vertex/Gemini, and Hugging Face patterns. Model identifier, provider revision, deployment, endpoint, framework package version, repository revision, and artifact content revision are independent concepts. A model name is no longer treated as immutable version evidence.

Offline package inventory covers Python requirements/PEP 621/Poetry plus Poetry, uv, and Pipenv locks, and npm manifests plus npm, Yarn, and pnpm locks. Exact lock versions override loose manifest constraints; package PURLs, direct/transitive status, origins, license declarations, dependency paths, source evidence, and `DEPENDS_ON` edges are preserved.

`VulnerabilityProvider` is provider-neutral. The first implementation, `OSVVulnerabilityProvider`, batches resolved PURLs only. `CachedVulnerabilityProvider` supplies a timestamped atomic JSON cache. Vulnerability enrichment is opt-in through `--vuln-enrichment`; default scans remain offline. Package presence, affected-version status, code reachability, and exploitability are separate. OSV matches do not claim reachability or exploitability.

`generate_agent_bom()` now emits `agentguard-agent-bom/3.0`; `generate_agent_bom_v2()` and CLI `--schema-version 2.0` are the explicit compatibility path. CycloneDX remains 1.7 and now emits OSS PURLs, ML model components, dependency references, and normalized vulnerability objects with `affects`. Supply-chain nodes and connected known-vulnerability paths extend provenance graph 1.0 additively. See `docs/AI_AGENT_BOM_V3.md`.

## Milestone 4 scanner-quality harness (September 7, 2026)

Milestone 4 adds `RuleQualityHarness`, `agentguard quality validate/report`, a Draft 2020-12 rule-quality schema, deterministic manifest/snapshot update scripts, two-sided skill false-positive coverage, identity/BOM/CycloneDX/attack-path regressions, explicit analyzer-error tests, and a complete-offline performance benchmark.

Every `RULE_COVERAGE.json` rule now records implementation status, actual analysis engine, languages, frameworks tested, positive fixtures, false-positive-oriented negative fixtures, expected evidence shape, known limitations, deterministic status, and named validation tests. The harness checks parity with the bundled 181-rule catalog and rejects unsupported validated claims or missing evidence paths.

The validated baseline is deliberately conservative: 8 rules meet the strict positive+negative fixture bar, 1 is partially validated, 135 have executable routes without dedicated two-sided tests, 35 require dedicated semantic/control-flow detectors, and 2 are network-conditional. These quality statuses do not alter the protected rule catalog or implementation-tier counts. See `docs/MILESTONE_4_SCANNER_QUALITY.md`.

## Post-Milestone 4 large-project memory correction (September 7, 2026)

A real-world nested Python scan exposed exponential abstract-location path growth in `AbstractStore.resolve()`. Each alias hop appended both the already-expanded current path and a second accumulated suffix; the container-depth bound was applied only later in `write()`. Deep call/control-flow combinations could therefore raise `MemoryError` before the bound ran.

Alias resolution now bounds paths during construction, terminates cycles by abstract-location base, and preserves the configured wildcard abstraction for paths deeper than `max_container_depth`. Inventory discovery also reuses the existing `CodeIntelligenceSession` index without rereading every Python source file into a redundant dictionary. The regression covers both a long alias chain and a cycle while the existing cross-file, attribute/container, sanitizer, and finding-identity tests protect taint semantics.

## Post-Milestone 4 large-project performance correction (September 7, 2026)

The scanner now constructs one deterministic repository file inventory per scan. Git worktrees use tracked plus non-ignored untracked files; non-Git inputs use a pruned `os.scandir` walk that never descends into ignored dependency/build/cache directories. Scanner, inventory, package, and skill stages share this inventory. Package manifests are indexed by filename, and Python source/AST state is reused by inventory and skill analysis.

The semantic engine caches function call enumeration, source-line offsets, target applicability, and source/sink rule lookup. A statement-local call evaluation cache prevents the finding pass and value pass from executing the same resolved callee twice. Callee frames copy only argument/receiver-reachable abstract state instead of the caller's entire accumulated store, while session-level data-flow edges remain complete and ordered with constant-time deduplication. Calls that have no tainted inputs, tainted receiver state, or transitive intrinsic source avoid an unnecessary return-flow traversal; every function still receives its normal root structural/semantic scan, and tainted/interprocedural flows continue through resolved calls.

Skill cross-context patterns with formerly unbounded whole-file wildcard chains now use equivalent linear ordered-token/comment matching. Provenance attribution indexes symbols, owned assets, and incoming relationships by normalized file/target and caches containing-symbol lookups instead of resolving every path against every symbol for every finding. A complete offline/default self-scan completed in 12.615325 seconds for 156 files and 39 findings with zero analysis errors; the pre-correction run had not completed after 90 seconds. This is an environment-specific regression measurement, not a universal throughput claim.

The self-scan initially exposed 1,026 findings, which was detector noise rather than a successful result. The native skill engine had been applying all 68 compatibility rules to ordinary source, documentation, sample reports, and rule-catalog content; the config analyzer also mapped a single lexical match to every rule whose descriptive metadata shared a hint word. Skill analysis is now scoped to discovered `SKILL.md`, `skill.*`, or skill/plugin manifest roots. Config detections use explicit rule mappings and ignore AgentGuard rule-catalog documents. Native rules that match the exact same resolved semantic flow are consolidated into one primary finding, and equivalent compatibility/static hits are retained under `engine_metadata.related_rules` rather than emitted as repeated top-level findings. Distinct conditions on the same line remain separate.

On the user's earlier 442-file `damn-vulnerable-ai-agent-main` target, the corrected default scan completed in 1.54 seconds with 11 findings, no repeated file/line groups, and zero analyzer errors. Manual evidence review confirmed that the remaining results describe the intentionally vulnerable credential, unsafe deserialization, skill-backdoor, prompt-override/disclosure, and credential-sharing examples. The correction rejects test/fake/example credential placeholders, README prose about unsafe commands, incidental substrings such as `head`, `stages`, or `references`, and safe negated skill guidance such as “never reveal.”

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

Agent BOM v3 is AgentGuard-specific and groups agents, normalized models/packages/vulnerabilities, static findings, versions, assets, and relationships. Agent BOM v2 remains available only as an explicit compatibility export. CycloneDX AI BOM remains the interoperability representation.

## Provenance graph

The user needs the scanner to produce data rich enough for a separate UI/UX designer and architect to build an interactive provenance/attack-path experience.

The scanner must return a structured graph contract; the UI should not infer graph semantics from arbitrary finding strings.

Graph output includes:

- typed asset, code, security and supply-chain nodes
- typed relationship edges with explicit/direct, inferred or transitive/derived nature
- evidence attached to edges (file/line/symbol/resolution when known)
- finding nodes with separate direct and transitive affected assets
- evidence nodes for source/propagation/sink flows
- precomputed, graph-connected `attack_paths[]`
- separate direct/transitive risk summaries and version identity on assets

Typical relationships include `DEFINES`, `IMPLEMENTED_BY`, `CALLS`, `PASSES_DATA_TO`, `RETURNS_TO`, `USES_MODEL`, `USES_TOOL`, `USES_SKILL`, `USES_MEMORY`, `USES_RETRIEVER`, `USES_MCP_SERVER`, `USES_GUARDRAIL`, `CONTAINS_NODE`, `EXPOSES_TOOL`, `EXPOSES_RESOURCE`, `EXPOSES_PROMPT`, `HAS_CAPABILITY`, `HAS_FINDING`, and `HAS_EVIDENCE`.

The UI should be able to select an attack path and simply highlight ordered node/edge IDs returned by Core.

## Reference repositories considered

The project previously reviewed concepts from:

- user repository: `akarshkn17/AgentGuard`
- NVIDIA SkillSpector
- Cisco AI Defense AI BOM
- `msaad00/agent-bom`

External projects are design/reference inputs unless explicitly integrated. Avoid runtime dependencies merely for conceptual reuse. `THIRD_PARTY_NOTICES.md` documents licensing considerations.

## Current validation snapshot

After the large-project memory, performance, and detector-noise corrections, the source suite reports 47 passing tests. Catalog validation still reports 181 valid rules, and the quality manifest validates with zero issues. In addition to the Milestone 1–4 gates, the suite checks bounded/cycle-safe alias resolution, file-inventory pruning, edge deduplication, linear matcher parity, non-skill scope rejection, explicit config-to-rule mapping, equivalent-flow consolidation, all per-rule quality records, false-positive behavior, stable fingerprints/entity/version IDs, Agent BOM and CycloneDX semantic snapshots, connected attack paths, visible analysis errors, and measured complete-offline performance. See `BUILD_VALIDATION.md` for the exact recorded run.

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
