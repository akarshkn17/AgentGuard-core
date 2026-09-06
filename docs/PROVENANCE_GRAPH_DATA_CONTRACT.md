# Provenance Graph Data Contract — UI/UX and Architecture Handoff

## Scope

AgentGuard Core produces **graph data**, not a UI layout. The frontend may use Cytoscape.js, React Flow, Sigma.js, D3, or another renderer without changing scanner logic.

Export:

```bash
agentguard graph . -o agentguard-provenance.json
# or
agentguard scan . --format graph
```

Schema identifier: `agentguard-provenance-graph/1.0`.

Milestone 2 extends this contract additively. New exports always include evidence-backed node/edge/attribution fields, while the JSON Schema continues to accept earlier 1.0 payloads.

## Top-level payload

```text
scan
summary
nodes[]
edges[]
attack_paths[]
ui_hints
```

## Node contract

Every newly generated node has a stable `id`, legacy renderer `kind`, `node_class`, `subtype`, `label`, source information, risk information and type-specific attributes. `node_class` is one of `asset`, `code`, `security`, or `supply_chain`.

### Asset nodes

Typical subtypes:

- repository
- agent / sub_agent / orchestrator / agent_proxy
- model / llm_endpoint / model_endpoint
- tool / mcp_tool / skill / plugin
- mcp_server / mcp_client / mcp_gateway / mcp_resource / mcp_prompt
- prompt / guardrail
- memory / vector_store / retriever / dataset / knowledge_base
- dependency
- capability

Important fields:

```json
{
  "id": "AGENT-...",
  "kind": "asset",
  "subtype": "agent",
  "category": "agentic",
  "label": "support-agent",
  "qualified_name": "app.agent",
  "framework": {"name": "langgraph", "version": "==0.6.4"},
  "version": {
    "id": "AGV-...",
    "value": "2.1.0",
    "scheme": "declared",
    "source": "agent_manifest",
    "evidence": {"manifest": ".well-known/agent-card.json"}
  },
  "source": {"file": "app.py", "line": 16},
  "risk": {
    "finding_count": 2,
    "max_severity": "Critical",
    "finding_ids": ["AGF-..."]
  },
  "attributes": {}
}
```

### Finding nodes

Finding nodes contain severity, rule ID, analysis type, description, remediation, mappings, fingerprint, `directly_affected_assets`, `transitively_affected_assets`, and attribution metadata. They allow the UI to render findings as first-class graph objects rather than only badges.

### Code nodes

Code nodes represent modules, classes, functions, methods, nested functions, and security-relevant API/external calls. Source ranges and qualified symbols link scanner evidence to actual implementations instead of nearby declarations.

### Supply-chain nodes

Resolved/unresolved OSS packages, model artifacts, and service/provider assets are `supply_chain` nodes. Package attributes include ecosystem, PURL, direct/transitive status, lock/manifest origins, dependency path, and vulnerability status. Known advisories are security nodes with subtype `known_vulnerability`; they retain independent affected-version, reachability, and exploitability states.

### Evidence nodes

Each taint/static evidence step can be represented as a node with subtype such as:

- `source`
- `propagator`
- `sink`
- `structural`
- `config`
- `ast`
- `permission`

Evidence nodes should normally be collapsed in the UI and expanded when a finding/attack path is selected.

## Edge contract

Every edge provides:

```json
{
  "id": "EDGE-...",
  "source": "AGENT-...",
  "target": "TOOL-...",
  "relation": "USES_TOOL",
  "directed": true,
  "relationship_type": "explicit/direct",
  "confidence": "exact",
  "derivation_method": "resolved-ast-reference",
  "source_evidence": [{"file": "app.py", "line": 16, "symbol": "app.agent"}],
  "evidence": [{"file": "app.py", "line": 16}],
  "finding_ids": [],
  "attributes": {"resolution": "exact"}
}
```

`relationship_type` distinguishes `explicit/direct`, `inferred`, and `transitive/derived`. Inferred edges retain resolver confidence, derivation method and source evidence. `evidence` remains as a compatibility alias for existing graph consumers.

Current relationship vocabulary includes:

- `DEFINES`
- `USES_AGENT`
- `CONTAINS_NODE`
- `USES_MODEL`
- `AGENT_USES_MODEL`
- `TOOL_USES_MODEL`
- `MODEL_ACCESSED_VIA`
- `MODEL_IMPLEMENTED_WITH_PACKAGE`
- `USES_LLM_ENDPOINT`
- `USES_TOOL`
- `USES_SKILL`
- `USES_MCP_SERVER`
- `CONNECTS_TO`
- `EXPOSES_TOOL`
- `EXPOSES_RESOURCE`
- `EXPOSES_PROMPT`
- `USES_MEMORY`
- `USES_RETRIEVER`
- `USES_VECTOR_STORE`
- `USES_GUARDRAIL`
- `HAS_CAPABILITY`
- `IMPLEMENTED_BY`
- `CALLS`
- `PASSES_DATA_TO`
- `RETURNS_TO`
- `IMPORTS_PACKAGE`
- `DEPENDS_ON`
- `HAS_VULNERABILITY`
- `HAS_FINDING`
- `HAS_EVIDENCE`
- `EVIDENCE_FLOW`

The vocabulary is intentionally extensible; UI code should treat unknown future relations as renderable edges rather than errors.

## Attack-path contract

One finding produces an `attack_paths[]` object when an affected asset and graph-connected evidence route can be established. The ordered path is composed from actual graph edges, not synthetic line proximity.

```json
{
  "path_id": "PATH-...",
  "finding_id": "AGF-...",
  "rule_id": "AIR-EXEC-001",
  "severity": "Critical",
  "title": "LLM or user input reaches shell command execution",
  "entry_node_id": "EVIDENCE-...",
  "impact_node_id": "EVIDENCE-...",
  "asset_node_id": "TOOL-...",
  "directly_affected_assets": ["TOOL-..."],
  "transitively_affected_assets": ["AGENT-..."],
  "node_ids": ["AGENT-...", "TOOL-...", "CODE-...", "AGF-...", "EVIDENCE-..."],
  "edge_ids": ["EDGE-..."],
  "evidence_node_ids": ["EVIDENCE-..."],
  "attribution": {"derivation_method": "reverse-call-ownership", "confidence": "exact"},
  "explanation": "...",
  "remediation": ["..."]
}
```

For every index `i`, `edge_ids[i]` connects `node_ids[i]` to `node_ids[i + 1]`. Taint evidence nodes retain source-to-propagator-to-sink order.

Optional vulnerability enrichment adds graph-connected supply-chain paths over real emitted relationships, for example agent → model → implementation package → vulnerable dependency → vulnerability. Package presence and an OSV affected-version response do not by themselves prove code reachability or exploitability; both remain `unknown` unless independent static evidence supports a stronger conclusion.

## Attribution semantics

Code finding ownership is resolved through finding evidence, containing symbols, explicit asset implementation ownership, reverse call traversal, and upstream inventory relationships. The most specific assets are recorded as direct; upstream agents/orchestrators are transitive. Exact declared-file ownership supports configuration findings, and the repository is the final fallback when no specific owner can be established. Nearest-line matching is not used as the primary attribution mechanism.

## UI behaviors recommended

The designer can safely plan for:

1. **Overview graph:** assets only; cluster by `category` or `subtype`.
2. **Risk overlay:** node border/badge based on `risk.max_severity`; show direct and transitive finding counts separately.
3. **Finding focus:** selecting a finding highlights affected asset and evidence path.
4. **Version drawer:** show `entity_id`, `version_id`, resolved version, source, framework version and digest separately.
5. **Edge inspector:** show relationship type, confidence, derivation method and source evidence.
6. **Attack path mode:** display `attack_paths[].node_ids` and `edge_ids`, dim unrelated graph elements.
7. **Progressive evidence:** evidence nodes hidden by default and expanded on demand.
8. **Filters:** entity type, category, framework, severity, rule ID, version source, capability and source file.

## Important architectural limitation

This graph is **static provenance/capability evidence**, not runtime telemetry. `USES_TOOL` means AgentGuard found a static relationship. It does not claim that the tool was actually invoked in production. Future runtime observations should be separate edge evidence with a different source/provenance marker rather than overwriting static evidence.
