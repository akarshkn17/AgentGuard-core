# AgentGuard — Next Development Work for Codex

## Milestone status

Milestones 1–3 passed their validation gates on September 6, 2026. Milestone 4 (scanner-quality evidence and regression harness) passed on September 7, 2026. Do not reopen them as broad rewrites. Extend them with focused regression tests when a detector, framework, package format, or provider fixture exposes a concrete gap.

Milestone 2 removed nearest-line ownership as the primary mechanism. Findings now resolve through evidence, code symbols, explicit implementation ownership, reverse call edges and upstream inventory relationships. Direct and transitive affected assets remain separate, and generated attack paths are connected by real emitted edges.

Milestone 3 made `agentguard-agent-bom/3.0` the default internal export, retained explicit Agent BOM v2 compatibility, and kept CycloneDX 1.7 schema-valid. Optional OSV enrichment submits resolved PURLs only and retains `unknown` reachability/exploitability unless separate evidence proves more.

Milestone 4 now makes the detector-quality backlog executable and auditable. `agentguard quality validate` must remain green, and `validated` must continue to require both vulnerable and false-positive-oriented safe fixtures. Current status is 8 validated, 1 partially validated, 135 implemented-unvalidated, 35 requiring dedicated detectors, and 2 network-conditional.

## Primary milestone: detector-quality completion

The highest-priority work is to convert catalog rules that are currently metadata-only or shallow semantic/control-flow placeholders into real executable detectors with regression coverage.

Use the quality report as the queue. First complete the partially validated `AIR-NET-001` negative fixture, then select high-severity `requires_dedicated_detector` entries, followed by high-severity `implemented_unvalidated` rules whose broad shared-analyzer behavior needs precision proof.

### Workflow for each rule

1. Read the rule's intent, severity, remediation, target types and existing detector status from the catalog/RULE_COVERAGE.
2. Decide the correct analysis mechanism: AST, config/manifest, interprocedural taint, control flow, call graph, inventory relationship, cross-file semantic analysis, or explicit network enrichment.
3. Build a minimal vulnerable fixture that should trigger.
4. Build a corresponding safe fixture that should not trigger.
5. Implement the detector without changing unrelated rule identities.
6. Ensure finding evidence explains why it fired and, for flow rules, contains source -> propagation -> sink evidence.
7. Run focused tests and then the complete suite.
8. Update `RULE_COVERAGE.json` only after tests prove the detector depth.
9. Run `python scripts/sync-rule-quality.py`, review the manifest diff, and require `agentguard quality validate` to pass before promoting status.

## Skill engine reconciliation

The current in-Core compatibility baseline is the 68 `NVS-*` rules from the user's catalog. Review newer upstream SkillSpector analyzers separately. Add new AgentGuard rules only after deciding whether they are genuinely new risks, overlap with existing AgentGuard rules, or should be merged/mapped.

High-value upstream deltas to inspect include insecure deserialization, SSRF, artifact integrity/concealed executable behavior, and improved AST/taint precision.

Do not copy upstream product shell features (CLI/MCP server/provider management) into Core merely for parity.

## Inventory/BOM deepening

Validate discovery against multiple realistic framework fixtures, including where practical:

- LangChain/LangGraph
- OpenAI Agents SDK
- Google ADK/Vertex agent patterns
- AWS Bedrock/AgentCore patterns
- Microsoft Semantic Kernel/AutoGen
- CrewAI
- generic MCP SDKs

For each, verify explicit agent discovery, tool/model/MCP/retrieval/memory relationships, and independent identity/version fields.

Milestone 3 currently covers normalized model fixtures for LangChain/OpenAI/Azure/Anthropic/Bedrock/Google/Hugging Face and Python/npm package lockfile formats. Future focused additions should cover JavaScript model SDK semantics, monorepo/workspace dependency identity, environment substitutions without static defaults, additional lockfile versions, and richer license evidence without weakening offline determinism.

## Provenance graph maintenance

Graph relationships must originate from scanner evidence, not invented presentation assumptions.

Milestone 2 provides the core evidence-backed graph. Future detector/framework work should extend it with focused fixtures for:

- additional framework-specific agent -> tool resolution
- agent -> MCP server/tool resolution
- model -> agent association
- retriever/vector-store/data-flow relations
- trust-boundary metadata
- capability propagation
- additional provider/package/import relationships when real framework fixtures expose missing links

Known-vulnerability and provider/package relations are now present. Preserve the explicit separation between package presence, affected-version match, static reachability, and exploitability.

Preserve evidence, confidence and derivation metadata on every generated edge. Keep direct and transitive risk separate. Do not prioritize visual UI implementation inside Core; Core returns the contract and the UI comes later.

## Quality gates

Before calling a milestone complete:

- all tests pass
- catalog validates
- no regression in existing 181 catalog entries unless a documented catalog migration is intentional
- both positive and negative fixtures exist for newly deepened detectors
- generated JSON/SARIF/BOM/graph outputs remain schema-valid
- wheel install smoke test works in a clean environment
- README/build validation are updated
