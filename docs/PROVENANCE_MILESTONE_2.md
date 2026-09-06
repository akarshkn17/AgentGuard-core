# Milestone 2 — Evidence-Backed Provenance Graph

Validated on September 6, 2026.

## Outcome

AgentGuard now attributes findings through scanner evidence, code symbols, symbol ownership and the call graph. Nearest-line matching is no longer the primary attribution mechanism.

The implementation reuses the bounded `CodeIntelligenceSession` introduced in Milestone 1. That session remains in memory and is deliberately excluded from serialized `ScanResult 1.2` payloads.

## Graph model

The graph retains the public identifier `agentguard-provenance-graph/1.0` and adds fields without removing existing fields. Nodes now declare a `node_class`:

- `asset` for repositories and discovered AI/agent assets;
- `code` for modules, classes, functions, methods and relevant external calls;
- `security` for findings and evidence;
- `supply_chain` for dependencies, model artifacts and service/provider assets.

Edges carry both the legacy `evidence` field and the explicit Milestone 2 provenance fields:

- `relationship_type`: `explicit/direct`, `inferred`, or `transitive/derived`;
- `confidence`;
- `derivation_method`;
- `source_evidence`.

Generated edges always populate those fields. They are optional in the 1.0 JSON Schema so previously exported 1.0 documents remain schema-compatible.

## Finding attribution

For code findings, attribution follows this evidence-backed route:

```text
finding evidence
  -> source/sink CodeSymbol
  -> containing function or method
  -> exact asset ownership where available
  -> reverse call graph to an owning tool or agent
  -> upstream inventory relationships to parent agents
```

`Finding.directly_affected_assets` contains the most specific owned asset reached by this process. `Finding.transitively_affected_assets` contains upstream assets reached through actual graph relationships. The collections are never flattened together.

For non-code/config findings, exact declared-file ownership is used when available. Repository attribution is the explicit final fallback when no more specific ownership can be proven. Line proximity is not used to guess an owner.

## Attack paths

`attack_paths[]` are ordered traversals over emitted graph edges. A path can include:

```text
agent -> tool -> implementation symbol -> called symbol -> finding -> evidence chain
```

Every adjacent pair in `node_ids` is connected by the corresponding entry in `edge_ids`. Taint evidence nodes preserve source, propagator and sink order.

## Tests and fixtures

Durable fixtures are under `tests/fixtures/provenance/`:

- `vulnerable_cross_file` verifies cross-file taint, direct tool ownership, transitive agent impact and a fully connected path;
- `safe_cross_file` verifies the equivalent safe flow does not produce a security path;
- `inferred_cross_file` verifies inferred call resolution retains confidence, derivation and source evidence.

Golden semantic projections are stored in `tests/golden/provenance-*.golden.json`. `tests/test_provenance.py` also validates generated vulnerable/safe graphs against the Draft 2020-12 schema and verifies compatibility with the pre-Milestone 2 graph 1.0 sample.

## Compatibility boundaries

- `ScanResult` remains `1.2`.
- the provenance graph remains `1.0` with additive fields;
- Agent BOM remains `agentguard-agent-bom/2.0`;
- CycloneDX export is unchanged;
- the rule catalog remains 181 rules and detector-tier counts are unchanged;
- no network vulnerability provider or Agent BOM v3 work is included. Those belong to Milestone 3.

## Static-analysis limitation

The graph represents statically observed or derived relationships, not runtime telemetry. Confidence and derivation explain how a relationship was established; they do not claim a call occurred in production.
