# AgentGuard — Next Development Work for Codex

## Milestone status

Milestone 1 (bounded Python code-intelligence foundation) passed its validation gate on September 6, 2026. Do not reopen it as a broad rewrite. Extend it with focused regression tests when a detector exposes a concrete resolution or flow gap.

The next program milestone is evidence-backed provenance attribution, but it must not begin without explicit user direction. The current graph v1 contract remains compatible and still uses nearest-file/line attribution as a fallback.

Before Milestone 2, use the new `CodeIntelligenceSession` symbol, call-edge and data-flow structures rather than creating another parser/index. Preserve direct versus transitive ownership and require evidence/confidence on inferred relationships.

## Primary milestone: detector-quality completion

The highest-priority work is to convert catalog rules that are currently metadata-only or shallow semantic/control-flow placeholders into real executable detectors with regression coverage.

### Workflow for each rule

1. Read the rule's intent, severity, remediation, target types and existing detector status from the catalog/RULE_COVERAGE.
2. Decide the correct analysis mechanism: AST, config/manifest, interprocedural taint, control flow, call graph, inventory relationship, cross-file semantic analysis, or explicit network enrichment.
3. Build a minimal vulnerable fixture that should trigger.
4. Build a corresponding safe fixture that should not trigger.
5. Implement the detector without changing unrelated rule identities.
6. Ensure finding evidence explains why it fired and, for flow rules, contains source -> propagation -> sink evidence.
7. Run focused tests and then the complete suite.
8. Update `RULE_COVERAGE.json` only after tests prove the detector depth.

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

## Provenance graph deepening

Graph relationships must originate from scanner evidence, not invented presentation assumptions.

Next improvements should include:

- stronger symbol/call resolution across files
- agent -> tool resolution
- agent -> MCP server/tool resolution
- model -> agent association
- retriever/vector-store/data-flow relations
- trust-boundary metadata
- capability propagation
- finding attachment to the most specific relevant asset
- source/sink attack paths that can cross functions/files

Do not prioritize visual UI implementation inside Core. Core returns the contract; UI comes later.

## Quality gates

Before calling a milestone complete:

- all tests pass
- catalog validates
- no regression in existing 181 catalog entries unless a documented catalog migration is intentional
- both positive and negative fixtures exist for newly deepened detectors
- generated JSON/SARIF/BOM/graph outputs remain schema-valid
- wheel install smoke test works in a clean environment
- README/build validation are updated
