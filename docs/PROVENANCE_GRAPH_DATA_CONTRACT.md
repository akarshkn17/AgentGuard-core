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

Every node has a stable `id`, `kind`, `subtype`, `label`, source information, risk information and type-specific attributes.

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

Finding nodes contain severity, rule ID, analysis type, description, remediation, mappings and fingerprint. They allow the UI to render findings as first-class graph objects rather than only badges.

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
  "evidence": [{"file": "app.py", "line": 16}],
  "finding_ids": [],
  "attributes": {"resolution": "exact"}
}
```

Current relationship vocabulary includes:

- `DEFINES`
- `USES_AGENT`
- `CONTAINS_NODE`
- `USES_MODEL`
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
- `HAS_FINDING`
- `HAS_EVIDENCE`
- `EVIDENCE_FLOW`

The vocabulary is intentionally extensible; UI code should treat unknown future relations as renderable edges rather than errors.

## Attack-path contract

One finding produces an `attack_paths[]` object even when the path is only a static evidence path. This lets the UI use one interaction model now and later evolve into multi-finding toxic-combination paths.

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
  "node_ids": ["TOOL-...", "AGF-...", "EVIDENCE-..."],
  "edge_ids": ["EDGE-..."],
  "explanation": "...",
  "remediation": ["..."]
}
```

## UI behaviors recommended

The designer can safely plan for:

1. **Overview graph:** assets only; cluster by `category` or `subtype`.
2. **Risk overlay:** node border/badge based on `risk.max_severity`; count badge from `risk.finding_count`.
3. **Finding focus:** selecting a finding highlights affected asset and evidence path.
4. **Version drawer:** show `entity_id`, `version_id`, resolved version, source, framework version and digest separately.
5. **Edge inspector:** show relationship evidence file/line and resolution metadata.
6. **Attack path mode:** display `attack_paths[].node_ids` and `edge_ids`, dim unrelated graph elements.
7. **Progressive evidence:** evidence nodes hidden by default and expanded on demand.
8. **Filters:** entity type, category, framework, severity, rule ID, version source, capability and source file.

## Important architectural limitation

This graph is **static provenance/capability evidence**, not runtime telemetry. `USES_TOOL` means AgentGuard found a static relationship. It does not claim that the tool was actually invoked in production. Future runtime observations should be separate edge evidence with a different source/provenance marker rather than overwriting static evidence.
