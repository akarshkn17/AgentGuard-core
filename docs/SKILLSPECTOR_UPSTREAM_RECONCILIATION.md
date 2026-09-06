# SkillSpector Upstream Reconciliation Boundary

## What v0.4 internalizes

The compatibility baseline for this release is the **68 `NVS-*` entries in the supplied AgentGuard risk catalog**. Their security-analysis behavior is routed through AgentGuard Core's native `agentguard-skill` engine; no SkillSpector executable is required.

The baseline covers the catalog's prompt/instruction, exfiltration, privilege, supply-chain, agency, output handling, prompt leakage, memory, tool misuse, persistence, trigger, AST, taint, YARA-like signature, MCP least-privilege and MCP tool-metadata categories.

## What is intentionally not copied into scanner Core

SkillSpector also contains product/runtime features that are not part of AgentGuard's scanner-detection engine boundary, for example:

- its own CLI UX and report renderer;
- MCP server transport;
- URL/Git/zip ingestion pipeline;
- batch scanning utility;
- provider-specific LLM orchestration;
- its own baseline/suppression format;
- its own risk-score/recommendation presentation.

AgentGuard already has its own CLI, result contract, reporting, CI gate and future service architecture, so duplicating those features inside Core would recreate the coupling this refactor is intended to remove.

## Upstream drift

NVIDIA SkillSpector is an independent Apache-2.0 project and continues to evolve. A future AgentGuard upgrade should therefore compare:

1. current upstream rule/pattern IDs and categories;
2. current upstream AST/taint/MCP analyzers;
3. changed remediation/explanation semantics;
4. new tests/fixtures and false-positive suppressions;
5. the AgentGuard risk catalog and its control mappings.

New upstream detections should be added as explicit new AgentGuard catalog entries or mapped to existing rules. Do not silently change an existing `NVS-*` rule's semantics without updating its rule version and regression fixture.

## Traceability policy

- Keep `origin_engine: skillspector` and the upstream/original rule ID.
- Keep AgentGuard's runtime engine as `agentguard-skill` when the implementation is native.
- Preserve Apache-2.0 attribution in `THIRD_PARTY_NOTICES.md`.
- Maintain behavior with AgentGuard-owned tests rather than requiring SkillSpector at runtime.
