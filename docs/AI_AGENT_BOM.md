# AI Inventory, AI BOM and Agent BOM

## What changed

The existing AgentGuard inventory already had stable entity IDs, content hashes, framework labels, and partial package-version detection. This build makes **categorization and version provenance explicit**.

Each inventory entity now carries:

- `entity_type`: exact technical asset type (`agent`, `tool`, `mcp_server`, `model`, `vector_store`, etc.);
- `category`: normalized family such as `agentic`, `mcp`, `tooling`, `model_runtime`, `data_retrieval`, `memory_state`, `safety`;
- `version`: best available version identity;
- `version_source`: `dependency_manifest`, `content_hash`, or another future declared source;
- `package_name` / `package_version`: framework dependency metadata when available;
- `content_hash`: immutable source-definition identity;
- `detection_source`: how the asset was discovered;
- `bom_ref`: stable reference used in BOM relationships.

## Version strategy

A framework-backed asset uses the declared package version/specification where it can be tied to a dependency manifest. A code-defined asset without a trustworthy declared semantic version uses a content-derived `sha256:` identity. This is intentionally more honest than reporting an invented version.

Future improvements can resolve exact lockfile versions (`uv.lock`, `poetry.lock`, `package-lock.json`, `pnpm-lock.yaml`) before falling back to manifest constraints.

## AI BOM

`agentguard bom . --kind aibom` emits CycloneDX 1.7 JSON. It includes AgentGuard entity type/category, version provenance, source location and static relationships as properties/dependencies.

## Agent BOM

`agentguard bom . --kind agent-bom` emits an AgentGuard-native agent view containing:

- agents/sub-agents/orchestrators;
- framework and version identity;
- source definition;
- inferred capabilities;
- directly related tools/models/MCP/memory/retrieval assets;
- full underlying asset/relationship lists for downstream registry import.

This is intentionally a Core capability, not a runtime integration with another BOM product.

## Reference taxonomy

The categorization design was informed by the broader component taxonomies exposed by Cisco AI BOM and the unified finding/remediation ideas in `agent-bom`, while retaining AgentGuard's own inventory IDs, AST discovery, relationships and output contract. See `THIRD_PARTY_NOTICES.md`.
