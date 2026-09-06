# AgentGuard Agent BOM v3

## Contract and compatibility

`agentguard-agent-bom/3.0` is AgentGuard's rich internal inventory and security contract. `generate_agent_bom()` and the CLI's `agent-bom` output use v3 by default. `generate_agent_bom_v2()` and `--schema-version 2.0` provide an explicit compatibility path. CycloneDX 1.7 remains the interoperability export.

The machine-readable JSON Schema is `docs/schemas/agent-bom-v3.schema.json`.

## First-class collections

The document contains:

- `agents`
- `models`
- `tools`
- `skills`
- `mcp_components`
- `data_retrieval_assets`
- `memory`
- `packages`
- `vulnerabilities`
- `static_findings`
- `relationships`
- `versions`
- `assets`, retained as the complete normalized inventory view

## Model identity

`ModelEntity` separates the logical model asset from provider naming and revision evidence:

- `model_id` and `logical_identity`
- `provider` and `model_identifier`
- independent `model_revision`
- deployment, endpoint/service, and access type
- framework package and its resolved package version
- configuration source and source location
- statically available parameters only
- local/downloaded repository and repository revision
- artifact content revision only when it is actually observed

A remote identifier such as `gpt-4o-mini` is not represented as an immutable version. Its revision remains empty/unknown unless separate evidence proves a revision. Hugging Face repository identifiers and requested revisions are also independent fields.

Supported Python patterns include LangChain/LangGraph wrappers, OpenAI and Azure OpenAI, Anthropic, AWS Bedrock, Google Vertex/Gemini, and Hugging Face Transformers. Literal, module-constant, and resolvable environment/configuration defaults retain their configuration source.

Normalized model relationships are `AGENT_USES_MODEL`, `TOOL_USES_MODEL`, `MODEL_ACCESSED_VIA`, and `MODEL_IMPLEMENTED_WITH_PACKAGE`.

## Package inventory

`PackageEntity` records normalized PyPI/npm identity, version, PURL, direct/transitive status, manifest and lockfile origins, dependency paths, licenses when declared by a lockfile, source evidence, and dependency IDs.

Sources currently include:

- Python: requirements files, PEP 621 and Poetry `pyproject.toml`, `poetry.lock`, `uv.lock`, and `Pipfile.lock`
- JavaScript/TypeScript: `package.json`, `package-lock.json`/npm shrinkwrap, Yarn lockfiles, and pnpm lockfiles

Exact lockfile versions take precedence over loose manifest constraints. `DEPENDS_ON` edges preserve resolved supply-chain structure. Unresolved constraints remain visible but are not submitted to a vulnerability provider.

## Optional vulnerability enrichment

`VulnerabilityProvider` is the Core provider boundary. `OSVVulnerabilityProvider` batches exact package PURLs through OSV's query-batch endpoint. `CachedVulnerabilityProvider` stores timestamped provider responses in an atomic JSON cache. Default scanning performs no network vulnerability query.

Normalized `VulnerabilityRecord` values include canonical ID, aliases, provider, severity/CVSS/CWE when supplied, affected package, affected ranges and fixes, references, publication/update/enrichment timestamps, and separate status fields for:

- package presence
- affected-version match
- reachability
- exploitability

OSV package matches set affected-version status to `affected`; reachability and exploitability remain `unknown`. AgentGuard asserts `reachable` only if future static evidence explicitly proves it.

Only package identity is transmitted to OSV. Customer source, prompts, findings, and inventory relationships are not transmitted.

## Provenance and CycloneDX

Package nodes, provider/service nodes, model nodes, and known-vulnerability security nodes participate in the existing provenance graph. Supply-chain paths are traversals over emitted semantic edges, including model-to-package, package dependencies, imports, and `HAS_VULNERABILITY`; no path is invented from line proximity.

CycloneDX output remains version 1.7. It emits package PURLs, ML models as `machine-learning-model`, software dependency references, and vulnerability `affects` references. Tests validate generated JSON using the official CycloneDX Python validator for schema 1.7.

## Commands

```powershell
agentguard bom . --kind agent-bom -o agentguard-agent-bom.json
agentguard bom . --kind agent-bom --schema-version 2.0 -o agentguard-agent-bom-v2.json
agentguard bom . --kind aibom -o agentguard-aibom.cdx.json
agentguard scan . --vuln-enrichment --vuln-cache .\.agentguard\cache\osv.json
agentguard graph . --vuln-enrichment -o agentguard-provenance-with-vulns.json
```
