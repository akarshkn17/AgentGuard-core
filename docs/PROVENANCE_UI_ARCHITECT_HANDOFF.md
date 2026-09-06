# AgentGuard Provenance — UI/UX + Architecture Handoff

This document answers the practical question: **what data will the scanner hand to the UI/platform?**

## 1. Scanner output boundary

AgentGuard Core returns a versioned `ScanResult`:

```text
ScanResult 1.2
├─ scan               repository + Git + scan metadata
├─ findings[]         normalized security findings
├─ inventory[]        AI/agent/MCP/tool/model/skill/data assets
├─ models[]           normalized model/provider/revision records
├─ packages[]         normalized Python/npm package records
├─ vulnerabilities[]  optional provider-normalized known advisories
├─ relationships[]    statically resolved asset-to-asset relations
├─ metrics
├─ errors[]
└─ artifacts[]
```

The graph exporter transforms the same result into `agentguard-provenance-graph/1.0`. Milestone 2 adds evidence-backed fields without removing the earlier 1.0 fields. The UI should consume these contracts; it should not parse source code itself.

## 2. Identity and version fields the UI can rely on

For an asset:

```text
entity_id       = stable logical asset identity
version_id      = identity of this observed version/revision
version         = human-readable declared/project/revision value, otherwise unknown
version_source  = agent_manifest | project_manifest | constructor | model_revision | git_tag | git_commit | content_hash | unknown
version_scheme  = declared | semver | git-tag | git-commit | content-hash | unknown
content_hash    = immutable source definition digest
framework       = langgraph/langchain/mcp/etc.
framework_version = package/framework dependency version
package_version = dependency/package version when relevant
```

**Do not use `framework_version` as the agent version, or a model identifier as an immutable model revision.** ModelEntity exposes provider/model identifier, revision, deployment, endpoint, access type, framework package version, and local repository revision separately.

A version drawer can therefore show:

```text
Agent: support-agent
Agent ID: AGENT-402...
Observed version ID: AGV-0B...
Agent version: 2.1.0
Version source: Agent Card
Framework: LangGraph
Framework version: ==0.6.4
Content digest: sha256:...
Git commit: ...
```

## 3. Asset node types

The scanner may emit:

```text
Repository
Agent / Sub-agent / Orchestrator / Agent Proxy
Tool / Function Tool / MCP Tool
MCP Server / MCP Client / MCP Gateway / MCP Resource / MCP Prompt
Model / LLM Endpoint / Model Endpoint / Embedding
Skill / Plugin
Prompt / Guardrail
Memory / Checkpoint Store
Retriever / Vector Store / Dataset / Knowledge Base / Feature Store / RAG Pipeline
Dependency
Software Package / Model Artifact / Service Provider
Known Vulnerability
Capability
Finding
Evidence
```

UI can retain `kind` for its broad renderer and use `node_class` for the Milestone 2 grouping: `asset`, `code`, `security`, or `supply_chain`. Use `subtype` for icons and filters. Code nodes include modules, classes, functions, methods, nested functions and relevant external calls.

## 4. Relationship data

Every relationship edge has:

```text
id
source
target
relation
directed
evidence[]       file + line
relationship_type explicit/direct | inferred | transitive/derived
confidence       deterministic | exact | high | medium | low | unresolved
derivation_method how the scanner established the relationship
source_evidence[] file + line + symbol/detail when known
finding_ids[]    findings tied to the edge/path
attributes       resolution and analyzer details
```

Typical relations:

```text
DEFINES
USES_AGENT
DELEGATES_TO
CONTAINS_NODE
IMPLEMENTED_BY
CALLS
PASSES_DATA_TO
RETURNS_TO
USES_MODEL
AGENT_USES_MODEL
TOOL_USES_MODEL
MODEL_ACCESSED_VIA
MODEL_IMPLEMENTED_WITH_PACKAGE
USES_LLM_ENDPOINT
USES_TOOL
USES_SKILL
USES_MCP_SERVER
CONNECTS_TO
EXPOSES_TOOL
EXPOSES_RESOURCE
EXPOSES_PROMPT
USES_MEMORY
USES_RETRIEVER
USES_VECTOR_STORE
USES_GUARDRAIL
HAS_CAPABILITY
IMPORTS_PACKAGE
DEPENDS_ON
HAS_VULNERABILITY
HAS_FINDING
HAS_EVIDENCE
EVIDENCE_FLOW
```

Unknown future relations should still render as generic directed edges.

## 5. Finding data available to UI

A finding provides:

```text
finding_id
fingerprint
rule_id + rule_version
title/name
severity
category
analysis_type
description
message
file + line + code
source_description
sink_description
detection_logic
remediation[]
evidence[]
CWE/control mappings
engine_metadata
directly_affected_assets[]
transitively_affected_assets[]
attribution
```

This supports both a finding drawer and finding nodes in graph mode.

## 6. Evidence path data

For source-to-sink rules, evidence can include:

```text
source      e.g. model output, user input, environment secret
propagator  assignment, function parameter, return, expression
sink        subprocess, network request, file write, database query
```

Other detectors may emit evidence subtypes such as:

```text
structural
config
ast
permission
metadata
signature
```

Each evidence element includes file, line, symbol and detail/code context where available.

## 7. `attack_paths[]`

The graph output gives an ordered, graph-connected path per attributable finding:

```text
path_id
finding_id
rule_id
severity
title
asset_node_id
directly_affected_assets[]
transitively_affected_assets[]
entry_node_id
impact_node_id
node_ids[]
edge_ids[]
evidence_node_ids[]
attribution
explanation
remediation[]
```

The UI can highlight exactly `node_ids` and `edge_ids` without recomputing a graph traversal. Every edge ID connects its same-index node to the following node. `evidence_node_ids` retain the scanner's source-to-sink order.

Direct impact means the finding was attributed to that asset through symbol/file ownership. Transitive impact means the asset is upstream through actual inventory/call relationships. UI badges and counts should not merge those meanings.

Later, graph-level correlation can add multi-finding/toxic-combination paths under the same contract.

Milestone 3 also returns connected known-vulnerability paths over package/model/import/dependency edges. The UI must display package presence, affected-version status, reachability, and exploitability separately. A provider match is not proof of reachable or exploitable code; current OSV-only paths normally show both as `unknown`.

## 8. Recommended UI views

### Inventory view

Table/cards for all AI assets with:

- type/category
- name and logical ID
- version and version source
- framework/framework version
- source file
- capabilities
- finding count/max severity

### Provenance overview

Show asset nodes only. Group by category; hide evidence/finding nodes initially.

### Finding focus

Selecting a finding:

1. highlight affected asset;
2. highlight its `attack_paths[]` node/edge IDs;
3. expand evidence nodes;
4. open finding details/remediation drawer.

### Agent focus

Selecting an agent should show only its neighborhood:

```text
agent → model
agent → tools
agent → MCP servers
agent → skill
agent → memory/retrieval
agent → capabilities
agent → findings
```

### Version/history view later

The current static artifact has one scan snapshot. A future SaaS persistence layer can join snapshots by `entity_id` and versions by `version_id`, enabling:

```text
v2.0.0 → v2.1.0
new tool added
model changed
permission/capability drift
new/resolved findings
```

No change to scanner identity fields is required for that future feature.

## 9. What the UI must NOT infer

A static `USES_TOOL` edge means source/config evidence resolves the relationship. It does **not** mean that tool was executed at runtime.

Future runtime telemetry should add evidence such as:

```text
evidence_source = runtime
trace_id
observed_at
call_count
runtime_identity
```

without replacing the static evidence.

## 10. Files to give the designer/architect

- `docs/PROVENANCE_GRAPH_DATA_CONTRACT.md` — field-level contract
- `docs/schemas/provenance-graph.schema.json` — machine-readable schema
- `docs/samples/agentguard-provenance.sample.json` — realistic sample payload
- `docs/samples/agentguard-agent-bom.sample.json` — agent-centric inventory/version example
- `docs/samples/agentguard-result.sample.json` — complete scanner result
