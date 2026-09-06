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

## SkillSpector-origin rules

The 68 `NVS-*` IDs from the supplied catalog are executed by the internal `agentguard-skill` engine. AgentGuard does **not** shell out to `skillspector` and does not require SkillSpector to be installed. The rules keep their `NVS-*` IDs for compatibility and traceability.

`NVS-SC4` and `NVS-SC5` require current advisory/package-maintenance data and therefore only perform live checks when `--network-enrichment` is explicitly enabled. All other catalogued `NVS-*` rules have deterministic local detectors, including AST, simple taint, permission/capability comparison, trigger/metadata checks, prompt/instruction patterns, and malware-signature heuristics.
