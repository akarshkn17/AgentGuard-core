# Code Intelligence Foundation — Milestone 1

## Status

Milestone 1 was implemented and validated on September 6, 2026. It is an internal Core refactor; public `ScanResult 1.2`, Agent BOM 2.0, provenance graph 1.0 and CycloneDX 1.7 contracts remain compatible.

## Per-scan architecture

`Scanner` creates one in-memory `CodeIntelligenceSession` for the repository's Python sources. The session owns:

- parsed modules and parse errors;
- a symbol index for modules, classes, functions, methods, nested functions, parameters and decorators;
- source ranges and containing-symbol lookup;
- call sites, resolved call edges and resolution confidence;
- bounded analysis limits and observed data-flow edges.

The same session is supplied to `ProjectPythonAnalyzer` and `InventoryDiscoverer`, avoiding two independent Python symbol indexes during one scan.

## Resolution

Resolution supports local and cross-file functions, absolute/relative imported aliases, nested functions, `self`/`cls` methods and locally constructed receiver objects. Each resolved call records a derivation method and `exact`, `high`, `medium`, `low` or `unresolved` confidence. Ambiguous suffix matches are not silently selected.

## Abstract memory and flow

The bounded abstract store represents locals, attributes, container keys/indices and return locations. It supports:

- assignment and bounded alias propagation;
- argument-to-parameter propagation;
- interprocedural return values;
- object receiver aliases for method calls;
- attribute and dictionary/list entry sensitivity;
- deterministic branch joins;
- bounded loop, recursion, context, alias, container and evidence growth.

Findings retain the existing ordered `EvidenceNode` contract. Internal `DataFlowEdge` objects provide a reusable basis for evidence-backed graph work in Milestone 2.

## Sanitizer policy

A sanitizer-looking function name no longer clears taint. Sanitizer results are explicit:

- `proven`
- `partial`
- `unverified`
- `absent`

Only sink-appropriate built-in contracts or conservative structural proof clear applicable labels. The current structural proof requires a statically declared literal allowlist, a rejecting guard and safe returns. Partial and unverified sanitizers remain in the evidence chain and do not suppress findings.

## Determinism and compatibility

Representative pre-Milestone-1 and post-Milestone-1 scans of `examples/vulnerable_agent` and `examples/multi_agent_demo` produced identical rule/finding-ID sets. The multi-agent fixture remains at 10 findings, 11 assets, 5 relationships, 37 provenance nodes, 41 edges and 10 attack paths.

## Known boundaries

- This is bounded static analysis, not complete pointer analysis or symbolic execution.
- Receiver inference currently relies on statically visible local construction and indexed class methods.
- Dynamic imports, monkey patching and reflective dispatch remain unresolved or low confidence.
- Container precision is bounded; deep/dynamic entries collapse to wildcard locations.
- The native skill analyzer remains independent and was not rewritten in this milestone.
- Provenance still uses its v1 nearest-file/line attribution fallback. Evidence-backed ownership and graph-derived attack paths are Milestone 2 work.
