# Rule Catalog Implementation

Source of truth: `docs/source/AgentGuard_Risk_Catalog_with_Controls.xlsx`.

## Catalog parity

- Total rules: **181**
- AgentGuard native: **113**
- AgentGuard native skill-security (`agentguard-skill`): **68**
- Rule validation: every bundled rule must have a unique ID, message, and remediation.

## Implementation tiers

- `deep-flow-capable`: **44** rules
- `structural-config-capable`: **34** rules
- `semantic-control-flow-enhancement`: **35** rules
- `native-static`: **64** rules
- `native-behavior-mismatch`: **2** rules
- `native-network-conditional`: **2** rules

`cataloged` and `fully precise detector` are intentionally different concepts. The scanner loads all 181 rules, but the rule coverage manifest records how each rule is currently evaluated so CI/reporting never implies unsupported precision.

## Milestone 1 analysis foundation

The Python deep-flow tier now runs on a bounded per-scan code-intelligence session with explicit symbols/source ranges, call resolution confidence, abstract locations for locals/attributes/container entries/returns, call/data-flow edge models and conservative sanitizer states. `AIR-EXEC-001` has dedicated vulnerable, safe and edge regression coverage for these capabilities. Other rule tiers and counts are unchanged; no rule is promoted merely because it can route through the shared engine.

## Milestone 2 provenance foundation

The same code-intelligence session now supports evidence-backed finding attribution and connected provenance/attack paths. This improves ownership and reporting for existing findings; it does not by itself deepen or promote any catalog detector. The 181 rule entries and all implementation-tier counts therefore remain unchanged at the Milestone 2 validation gate.

## Milestone 3 BOM and supply-chain foundation

Agent BOM v3 adds normalized model, Python/npm package, dependency, and optional OSV vulnerability records plus supply-chain provenance. This is inventory/enrichment infrastructure, not evidence that any catalog detector became deeper. The 181 rule entries and all implementation-tier counts therefore remain unchanged at the Milestone 3 validation gate.

## Milestone 4 scanner-quality evidence

Every rule now carries a quality record in `RULE_COVERAGE.json`: implementation status, analysis engine, languages, tested frameworks, positive/negative fixtures, expected evidence shape, known limitations, deterministic status, and validation tests. The quality harness validates all 181 records and rejects `validated` when positive and negative evidence is absent.

The conservative validated status is:

```text
validated                         8
partially_validated               1
implemented_unvalidated         135
requires_dedicated_detector      35
network_conditional               2
```

Implementation-tier counts remain unchanged because Milestone 4 measures evidence rather than deepening detectors. See `docs/MILESTONE_4_SCANNER_QUALITY.md`.

## SkillSpector-origin rules

The 68 `NVS-*` IDs from the supplied catalog are executed by the internal `agentguard-skill` engine. AgentGuard does **not** shell out to `skillspector` and does not require SkillSpector to be installed. The rules keep their `NVS-*` IDs for compatibility and traceability.

`NVS-SC4` and `NVS-SC5` require current advisory/package-maintenance data and therefore only perform live checks when network enrichment is explicitly enabled. `--network-enrichment` remains a compatibility alias for `--vuln-enrichment`. All other catalogued `NVS-*` rules have deterministic local detectors, including AST, simple taint, permission/capability comparison, trigger/metadata checks, prompt/instruction patterns, and malware-signature heuristics.
