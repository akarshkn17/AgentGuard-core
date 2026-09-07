# AgentGuard v0.4.0 Build Validation

Validated in the build environment through September 7, 2026.

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

## Milestone 2 evidence-backed provenance

Core now builds explicit asset, code, security and supply-chain nodes from inventory plus the shared code-intelligence session. Generated relationships contain source evidence, confidence, derivation method and an `explicit/direct`, `inferred`, or `transitive/derived` classification.

Validated provenance behavior includes:

- evidence/symbol/ownership/call-graph finding attribution without nearest-line ownership guessing;
- separate `directly_affected_assets` and `transitively_affected_assets`;
- cross-file tool ownership and upstream agent impact;
- inferred call edges retaining medium confidence and `unique-suffix` derivation;
- modules, functions and relevant external-call code nodes;
- ordered source/propagator/sink evidence nodes;
- attack paths whose node pairs are connected by the returned edge IDs;
- vulnerable and safe golden semantic projections;
- Draft 2020-12 validation for newly generated graphs and compatibility with the earlier graph 1.0 sample.

Durable fixtures are under `tests/fixtures/provenance/`. See `docs/PROVENANCE_MILESTONE_2.md`.

## Milestone 3 Agent BOM and supply-chain inventory

Core now emits `agentguard-agent-bom/3.0` by default while retaining `generate_agent_bom_v2()` and CLI `--schema-version 2.0` as an explicit compatibility path. `ScanResult 1.2` is extended additively with normalized model, package, and vulnerability collections.

Validated behavior includes:

- LangChain/LangGraph, OpenAI, Azure OpenAI, Anthropic, Bedrock, Google Vertex/Gemini, and Hugging Face model patterns;
- model identifier, revision, deployment, endpoint, framework package version, repository revision, and content revision kept independent;
- resolvable environment defaults and static model parameters with configuration provenance;
- requirements, PEP 621/Poetry, Poetry/uv/Pipenv lock, package.json, npm/Yarn/pnpm lock discovery;
- exact lockfile versions preferred over loose constraints, PyPI/npm PURLs, direct/transitive status, licenses, source evidence, dependency paths, and `DEPENDS_ON` edges;
- provider-neutral vulnerability records, batched OSV PURL queries, timestamped atomic cache, and an offline default;
- separate package-presence, affected-version, reachability, and exploitability status without unsupported exploitability claims;
- connected package/model/vulnerability provenance paths over emitted relationships;
- Agent BOM v3 Draft 2020-12 schema validation;
- CycloneDX 1.7 packages, ML models, dependency graph, and vulnerability `affects` references validated by the official CycloneDX Python validator.

Durable fixtures are under `tests/fixtures/milestone3/`; focused tests are in `tests/test_milestone3.py`. See `docs/AI_AGENT_BOM_V3.md`.

## Milestone 4 scanner-quality harness

Every rule in `RULE_COVERAGE.json` now tracks implementation status, analysis engine, languages, tested frameworks, positive fixtures, false-positive-oriented negative fixtures, expected evidence shape, known limitations, deterministic status, and named regression tests.

Validated behavior includes:

- Draft 2020-12 schema validation for exactly 181 rule-quality records;
- catalog engine/analysis parity and unique/missing record detection;
- fixture/test path and named test-anchor validation;
- rejection of unsupported `validated` claims;
- explicit quality-gap reporting instead of treating analyzer routing as proof;
- false-positive-oriented safe skill fixtures alongside positive fixtures;
- repeat-scan finding fingerprint, entity ID, and version ID stability;
- Agent BOM v3 and CycloneDX semantic golden snapshots;
- official CycloneDX 1.7 strict validation;
- connected attack-path regression and visible analysis-error behavior;
- a complete-offline performance benchmark that does not disable normal analysis.

Quality status at this gate:

```text
validated                         8
partially_validated               1
implemented_unvalidated         135
requires_dedicated_detector      35
network_conditional               2
manifest validation issues        0
```

See `docs/MILESTONE_4_SCANNER_QUALITY.md`.

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
47 passed in 80.13s
```

Coverage exercised:

- all 181 bundled rules load and validate;
- source→sink/interprocedural finding enrichment;
- internal `agentguard-skill` findings without external SkillSpector;
- JSON/SARIF/CSV/JUnit/HTML exporters;
- CycloneDX 1.7 AI BOM, Agent BOM v3, and explicit Agent BOM v2 compatibility;
- stable entity identity vs separate version identity;
- agent-card version discovery and framework-version separation;
- provenance graph nodes, relationships, findings, evidence and attack paths.
- code symbol/source-range indexing and containing-symbol lookup;
- call resolution confidence and explicit call/data-flow structures;
- vulnerable attribute/container and cross-file/nested flows;
- safe allowlist, numeric conversion and clean container-entry cases;
- partial/fake sanitizer and bounded-recursion edge cases;
- cycle-safe alias resolution with container paths bounded before allocation;
- SCM-aware, ignore-pruned shared file inventory and ordered O(1) edge deduplication;
- linear cross-context skill matching with positive and negative parity checks;
- representative pre/post-refactor finding-ID parity.
- evidence-backed direct/transitive finding attribution;
- explicit, inferred and derived relationship provenance;
- connected cross-file attack paths and ordered evidence chains;
- provenance golden snapshots and JSON Schema compatibility.
- multi-provider model detection and identifier/revision/configuration-source separation;
- Python/npm manifests and lockfile resolution with direct/transitive dependency paths;
- optional OSV batch/cache normalization with offline and unresolved-version negative tests;
- known-vulnerability provenance whose ordered node pairs are connected by returned edge IDs;
- Agent BOM v3 and provenance JSON Schema validation;
- official CycloneDX 1.7 strict validation, including package PURL/model/dependency/vulnerability semantics.
- all 181 per-rule quality records and rejection of unproven validated claims;
- false-positive-oriented native skill regressions;
- deterministic Agent BOM/CycloneDX snapshots and identity IDs;
- complete-offline performance and explicit analyzer-error status.

## Built wheels

```text
dist/agentguard_core-0.4.0-py3-none-any.whl
dist/agentguard_cli-0.4.0-py3-none-any.whl
```

Core wheel inspection confirms bundled catalog/runtime assets and Milestone 3 modules:

- `agentguard_core/rules/builtin/native_catalog.yaml`
- `agentguard_core/rules/builtin/skill_catalog.yaml`
- `agentguard_core/rules/catalog_manifest.json`
- `agentguard_core/skill_analyzer.py`
- `agentguard_core/provenance.py`
- `agentguard_core/bom.py`
- `agentguard_core/bom_models.py`
- `agentguard_core/model_inventory.py`
- `agentguard_core/package_inventory.py`
- `agentguard_core/vulnerabilities.py`
- `agentguard_core/quality.py`

## Fresh-wheel smoke test

Both wheels were rebuilt from the Milestone 4 source and installed over the editable packages with dependencies held constant. The installed CLI validated the catalog and quality manifest; the Core wheel exposed `RuleQualityHarness`:

```text
AgentGuard CLI 0.4.0 · Core 0.4.0
Valid: 181 rules
Valid quality manifest: 181 rules, 8 fully fixture-validated
RuleQualityHarness
```

The editable development packages were restored after the wheel smoke test.

## Representative Milestone 2 graph

The complete catalog scan of `examples/multi_agent_demo` produced:

```text
status: completed
findings: 10
inventory assets: 11
inventory relationships: 5
analyzer errors: 0
provenance nodes: 44
provenance edges: 83
attack paths: 10
node classes: asset 8, supply_chain 4, code 7, security 25
edge natures: explicit/direct 70, transitive/derived 13
findings with direct attribution: 10
findings with transitive attribution: 8
```

This section remains the representative Milestone 2 graph snapshot. Milestone 3 extends graph 1.0 additively and makes Agent BOM v3 the default; Agent BOM v2 remains an explicit compatibility export.

## Representative Milestone 3 inventory

The complete catalog scan of `tests/fixtures/milestone3/full_project` produced:

```text
status: completed
findings: 3
inventory assets: 21
inventory relationships: 18
models: 7
model providers: anthropic, aws-bedrock, azure-openai, google, huggingface, openai
packages: 8 (4 direct, 4 transitive)
vulnerabilities: 0 (offline default)
analyzer errors: 0
provenance nodes: 44
provenance edges: 76
attack paths: 3
```

The deterministic provider fixture adds one affected package advisory and verifies a connected agent → model → package → vulnerability path while leaving reachability and exploitability `unknown`.

## Representative Milestone 4 benchmark

Three complete offline/default scans of `tests/fixtures/milestone3/full_project` produced:

```text
minimum: 0.713876 seconds
median:  0.739980 seconds
maximum: 0.748094 seconds
budget: 30 seconds
files: 5
findings: 3
inventory assets: 21
analysis errors: 0
status: completed
```

The performance result is an environment-specific regression baseline, not a universal customer throughput claim.

## Post-Milestone 4 large-repository performance benchmark

A complete offline/default scan of this repository after the performance correction produced:

```text
duration: 12.615325 seconds
files: 156
findings: 39
inventory assets: 60
analysis errors: 0
status: completed
```

The same self-scan had not completed after 90 seconds before the correction was fully applied. The correction shares one Git-aware/pruned file inventory across scanner stages, indexes package paths/rules/calls/source lines/provenance ownership, avoids copying unrelated abstract state into call frames, deduplicates data-flow edges in constant time, reuses Python source/AST state, and replaces unbounded whole-file skill regex chains with equivalent linear ordered-token matching. Default analysis, the 181-rule catalog, taint evidence, BOM output, and provenance attribution remain enabled.

A follow-up noise correction reduced the self-scan from 1,026 mostly irrelevant/repeated findings to 39. Skill rules now execute only inside discovered skill/plugin roots, config checks map directly to relevant rule IDs instead of fuzzy catalog-description keywords, rule catalog documents are not treated as vulnerable runtime configuration, and equivalent native/cross-engine flow hits are returned once with the secondary rule identities retained in `engine_metadata.related_rules`.

The previously used `damn-vulnerable-ai-agent-main` repository completed in 1.54 seconds for 442 files with 11 findings, no repeated file/line groups, and zero analyzer errors. The remaining evidence was manually reviewed and points to six non-placeholder hardcoded credentials, unsafe pickle loading, an executable skill backdoor, prompt disclosure/override instructions, and credential-sharing instructions. Test placeholder keys, README explanations, ordinary JavaScript words such as `head`/`stages`/`references`, and a safe “never reveal” instruction were suppressed.

## Sample artifacts

See `docs/samples/`:

- `agentguard-result.sample.json`
- `agentguard-agent-bom.sample.json`
- `agentguard-aibom.sample.cdx.json`
- `agentguard-provenance.sample.json`

## Known precision boundary

The supplied catalog is fully bundled, but 35 native AgentGuard entries are explicitly marked `semantic-control-flow-enhancement`. They remain valid rule/catalog definitions routed through existing analyzers; specialized detector deepening/regression fixtures are still required before claiming the same precision level as deep-flow rules. The coverage manifest makes this visible instead of silently omitting them.

For the SkillSpector-origin catalog baseline, 64 checks are offline deterministic, 2 use deterministic behavior/description mismatch logic, and 2 require explicit `--network-enrichment` for current advisory/maintenance data.
