# Milestone 4 — Scanner Quality Harness

## Purpose

Milestone 4 makes detector quality auditable without equating catalog presence, analyzer routing, or broad matching with proven precision. It does not add or remove catalog rules and does not promote any detector merely because the shared analysis engine can execute it.

## Per-rule quality contract

All 181 entries in `RULE_COVERAGE.json` now track:

- `implementation_status`
- `analysis_engine`
- `languages`
- `frameworks_tested`
- `positive_fixtures`
- `negative_fixtures`
- `expected_evidence_shape`
- `known_limitations`
- `deterministic_status`
- `validation_tests`

The manifest conforms to `docs/schemas/rule-coverage.schema.json`. `RuleQualityHarness` additionally checks catalog parity, exact engine/analysis metadata, unique rule coverage, required fields, fixture paths, named test files/anchors, status consistency, and summary counts.

## Status meanings

- `validated`: dedicated positive and false-positive-oriented negative fixtures plus named regression tests exist.
- `partially_validated`: some direct regression evidence exists, but two-sided rule-specific coverage is incomplete.
- `implemented_unvalidated`: an executable analyzer route exists, but dedicated positive/negative precision evidence is missing.
- `requires_dedicated_detector`: catalog intent is present, but the specialized semantic/control-flow detector is not proven.
- `network_conditional`: execution depends on explicitly enabled external data and is not treated as deterministic offline evidence.

At this milestone gate:

```text
validated                         8
partially_validated               1
implemented_unvalidated         135
requires_dedicated_detector      35
network_conditional               2
total                            181
```

This is intentionally not reported as “181 implemented rules.” Only 8 currently satisfy the strict two-sided fixture definition.

## Regression coverage

`tests/test_milestone4.py` adds:

- full 181-rule manifest/schema validation;
- rejection of unsupported `validated` claims;
- positive and false-positive-oriented negative checks for the currently validated native skill rules;
- repeat-scan finding fingerprint and inventory entity/version ID checks;
- Agent BOM v3 semantic snapshots covering model, package, dependency, relationship, entity, and version identity;
- CycloneDX 1.7 semantic snapshots plus official schema validation;
- connected attack-path checks;
- explicit analysis-error visibility checks;
- a complete-offline scan performance budget.

Existing Milestone 1–3 tests continue to cover deep source-to-sink evidence, provenance golden snapshots, vulnerability semantics, model detection, package detection, and dependency paths.

Snapshot refresh is explicit through `scripts/update-quality-goldens.py`; changes must be reviewed, not accepted automatically. `scripts/sync-rule-quality.py` deterministically maintains per-rule fields while preserving the protected rule IDs and implementation tiers.

## Performance benchmark

`scripts/benchmark-scanner.py` measures complete offline/default scans. It records every run, min/median/max, scan counts, analyzer errors, and optional budget status. It does not disable inventory, rules, skill analysis, or other normal defaults to manufacture a better result.

```powershell
python .\scripts\benchmark-scanner.py .\tests\fixtures\milestone3\full_project `
  --runs 3 `
  --budget-seconds 30 `
  --output .\agentguard-performance.json
```

## CLI

```powershell
agentguard quality validate --coverage .\RULE_COVERAGE.json
agentguard quality report --coverage .\RULE_COVERAGE.json -o .\agentguard-quality-report.json
```

Validation exits with code 2 for invalid catalog metadata, missing records/fields/fixtures/tests, inconsistent network/determinism status, or an unsupported validated claim.

## Remaining work

The 135 `implemented_unvalidated`, 35 `requires_dedicated_detector`, 1 partially validated, and 2 network-conditional entries are an actionable backlog. Promotion should happen one rule at a time only after the detector has both a vulnerable fixture and a realistic safe/negative fixture with the expected evidence shape.
