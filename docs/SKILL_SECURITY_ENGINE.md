# AgentGuard Native Skill Security Engine

## Purpose

AgentGuard v0.4 removes the runtime dependency on the NVIDIA SkillSpector executable for the 68 `NVS-*` rules in the supplied AgentGuard risk catalog. Those rule IDs are preserved for compatibility and traceability, but execution is performed by `agentguard_core.skill_analyzer.SkillSecurityAnalyzer`.

## What runs locally

The native engine evaluates skill directories, `SKILL.md`, manifests, source files, and relevant dependency files using deterministic analysis:

- prompt-injection and anti-refusal instruction patterns;
- hidden/invisible text and Unicode-deception checks;
- data-exfiltration and credential/file access patterns;
- excessive agency, privilege and unsafe-default checks;
- dependency pinning and typosquat checks;
- Python AST checks for `exec`, `eval`, dynamic imports, subprocess/process execution, compile and reflective `getattr` sinks;
- lightweight local taint tracking for external/file/secret values reaching execution or network sinks;
- declared-permission versus observed-capability comparison;
- trigger-abuse and MCP/tool metadata checks;
- malware/webshell/miner/exploit signature heuristics;
- deterministic stated-purpose versus observed-behavior comparison.

`NVS-SC4` (known vulnerable dependencies) and `NVS-SC5` (abandoned dependencies) need current external package/advisory data. They remain native AgentGuard rules but only do the live lookup when the user explicitly supplies `--network-enrichment`. The default scanner remains offline and deterministic.

## Upstream relationship

NVIDIA SkillSpector is Apache-2.0 licensed and remains a design/behavior reference. AgentGuard does not hide that origin: bundled `NVS-*` rules contain origin metadata and retain their compatibility IDs. The code in this build is an AgentGuard-native implementation rather than a subprocess wrapper.

Current upstream SkillSpector continues to evolve, so future upgrades should be handled as an explicit rule/analyzer reconciliation exercise rather than silently replacing AgentGuard behavior.
