# AgentGuard v0.4.0 Build Validation

Validated in the build environment on September 6, 2026.

## Milestone 1 code intelligence

Core now creates one bounded in-memory code-intelligence session per scan. It provides explicit source ranges, symbols, call sites, call edges, data-flow edges, abstract locations/values, resolution confidence and sanitizer results. Python analysis and inventory share the session's symbol index.

Validated analysis behavior includes:

- cross-file and imported-alias call resolution;
- methods, locally constructed receivers and nested functions;
- argument-to-parameter and return-value propagation;
- object attribute and dictionary/list entry taint;
- bounded aliases, loops, recursion, contexts and evidence paths;
- `proven`, `partial`, `unverified` and `absent` sanitizer state;
- removal of name-only sanitizer trust;
- ordered source-to-sink evidence and deterministic finding fingerprints;
- parse failures surfaced once through `ScanResult.errors`.

Durable vulnerable, safe and edge fixtures are under `tests/fixtures/code_intelligence/`.

## Catalog validation

Source of truth: `docs/source/AgentGuard_Risk_Catalog_with_Controls.xlsx`.

```text
181 total rules
113 AgentGuard native rules
68 SkillSpector-origin compatibility rules
0 duplicate rule IDs
0 missing message/remediation validation failures
```

Bundled runtime engines:

```text
agentguard       113
agentguard-skill  68
```

The `NVS-*` rules do not require the SkillSpector executable at runtime.

## Rule implementation tiers

`RULE_COVERAGE.json` records detector depth:

```text
native-static                       64
native-behavior-mismatch             2
native-network-conditional           2
deep-flow-capable                   44
structural-config-capable           34
semantic-control-flow-enhancement   35
```

All catalog rules are present; the tier field prevents catalog presence from being confused with identical detector precision.

## Source tests

```text
18 passed in 10.11s
```

Coverage exercised:

- all 181 bundled rules load and validate;
- source→sink/interprocedural finding enrichment;
- internal `agentguard-skill` findings without external SkillSpector;
- JSON/SARIF/CSV/JUnit/HTML exporters;
- CycloneDX AI BOM and Agent BOM v2;
- stable entity identity vs separate version identity;
- agent-card version discovery and framework-version separation;
- provenance graph nodes, relationships, findings, evidence and attack paths.
- code symbol/source-range indexing and containing-symbol lookup;
- call resolution confidence and explicit call/data-flow structures;
- vulnerable attribute/container and cross-file/nested flows;
- safe allowlist, numeric conversion and clean container-entry cases;
- partial/fake sanitizer and bounded-recursion edge cases;
- representative pre/post-refactor finding-ID parity.

## Built wheels

```text
dist/agentguard_core-0.4.0-py3-none-any.whl
dist/agentguard_cli-0.4.0-py3-none-any.whl
```

Core wheel inspection confirms bundled catalog/runtime assets:

- `agentguard_core/rules/builtin/native_catalog.yaml`
- `agentguard_core/rules/builtin/skill_catalog.yaml`
- `agentguard_core/rules/catalog_manifest.json`
- `agentguard_core/skill_analyzer.py`
- `agentguard_core/provenance.py`
- `agentguard_core/bom.py`

## Installed-wheel smoke test

The installed v0.4 wheel pair scanned `examples/multi_agent_demo`:

```text
AgentGuard CLI 0.4.0 · Core 0.4.0
Valid: 181 rules
status: completed
findings: 10
inventory assets: 11
relationships: 5
analyzer errors: 0
Agent BOM schema: agentguard-agent-bom/2.0
agents: 1
provenance nodes: 37
provenance edges: 41
attack paths: 10
```

Resolved agent example:

```text
name: support-agent
entity_id: AGENT-402ceaa3621c3c2b
version_id: AGV-0B28632D025A3B8A3582
agent version: 2.1.0
agent version source: agent_manifest
framework: langgraph
framework version: ==0.6.4
```

This validates that logical asset identity, asset version identity and framework package version are not conflated.

## Sample artifacts

See `docs/samples/`:

- `agentguard-result.sample.json`
- `agentguard-agent-bom.sample.json`
- `agentguard-aibom.sample.cdx.json`
- `agentguard-provenance.sample.json`

## Known precision boundary

The supplied catalog is fully bundled, but 35 native AgentGuard entries are explicitly marked `semantic-control-flow-enhancement`. They remain valid rule/catalog definitions routed through existing analyzers; specialized detector deepening/regression fixtures are still required before claiming the same precision level as deep-flow rules. The coverage manifest makes this visible instead of silently omitting them.

For the SkillSpector-origin catalog baseline, 64 checks are offline deterministic, 2 use deterministic behavior/description mismatch logic, and 2 require explicit `--network-enrichment` for current advisory/maintenance data.
