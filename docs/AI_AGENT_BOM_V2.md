# AI Inventory and Agent BOM v2

## Why the v0.3 model was changed

A component identity is not a version. A framework version is not necessarily an agent version, and a source-code digest is not a semantic version. v0.4 separates these concepts.

## Identity and version model

Every inventory asset can expose:

| Field | Meaning |
|---|---|
| `entity_id` | Stable logical identity for the asset across scans/versions. |
| `version_id` | Stable identity for this specific observed version/revision of the asset. |
| `version` | Human-readable asset version/revision. |
| `version_source` | Where AgentGuard obtained the version. |
| `version_scheme` | `declared`, `git-tag`, `git-commit`, `content-digest`, `model-id`, or `unknown`. |
| `version_evidence` | Evidence explaining how the version was resolved. |
| `framework` | Agent framework, e.g. `langgraph`. |
| `framework_version` | Version of that framework package. |
| `package_name` / `package_version` | Package that provides the detected construct and its declared dependency version. |
| `content_hash` | SHA-256 of the detected definition/snapshot. |

Example:

```json
{
  "entity_id": "AGENT-402ceaa3621c3c2b",
  "version_id": "AGV-0B28632D025A3B8A3582",
  "name": "support-agent",
  "entity_type": "agent",
  "version": "2.1.0",
  "version_source": "agent_manifest",
  "version_scheme": "declared",
  "version_evidence": {
    "manifest": ".well-known/agent-card.json",
    "declared_version": "2.1.0"
  },
  "framework": "langgraph",
  "framework_version": "==0.6.4"
}
```

## Version resolution priority

For code assets AgentGuard uses explicit evidence rather than inventing semantic versions:

1. agent/skill/card/constructor declared version;
2. project manifest version (`pyproject.toml` / `package.json`) for repository-owned code assets;
3. exact Git tag;
4. Git commit;
5. content revision digest (`rev-<sha>`).

Models use their concrete model identifier as a `model-id` version when available.

## Inventory discovery in v0.4

The scanner now looks for:

- Python agent constructors and agent subclasses;
- LangGraph graph/orchestrator nodes;
- ordinary functions referenced as agent tools, not only decorated tools;
- models referenced as variables or literal model IDs;
- MCP server/client/tool/resource/prompt constructs and exposure relationships;
- prompts, memory, vector stores, retrievers and guardrail-like constructors;
- Agent Card / agent manifest files including `.well-known/agent-card.json`;
- skill manifests and skill versions;
- basic JavaScript/TypeScript agent/model/MCP constructor patterns;
- declared dependencies;
- derived capabilities such as process execution, network egress, file access and database queries.

## Agent BOM v2 structure

`agentguard-agent-bom.json` contains:

- repository/scan identity;
- summary counts;
- each agent with `agent_id` and `agent_version_id`;
- version evidence;
- framework and framework version;
- source definition;
- capabilities;
- directly related model/tool/MCP/skill/memory assets;
- complete asset inventory;
- version index;
- relationships.

This is intended to become the stable input for registry, UI, provenance, and future SaaS ingestion.
