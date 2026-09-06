# Third-Party Design and Compatibility References

AgentGuard v0.4 was developed with reference to these Apache-2.0 open-source projects:

- **NVIDIA SkillSpector** — https://github.com/NVIDIA/SkillSpector — Apache License 2.0.
- **Cisco AI BOM** — https://github.com/cisco-ai-defense/aibom — Apache License 2.0.
- **agent-bom** by msaad00 — https://github.com/msaad00/agent-bom — Apache License 2.0.

## NVIDIA SkillSpector compatibility

The user-supplied AgentGuard risk catalog contains 68 SkillSpector-origin rule entries. AgentGuard preserves their `NVS-*` compatibility IDs and origin metadata for traceability. This build executes those rules through AgentGuard's own `agentguard-skill` scanner engine rather than requiring or launching the SkillSpector executable at runtime.

SkillSpector's publicly documented categories, analyzer behavior and remediation concepts were used as compatibility/design references. Current upstream SkillSpector continues to evolve independently; AgentGuard's compatibility baseline is the 68 entries in the supplied risk catalog unless a later reconciliation explicitly updates that baseline.

## AI/Agent BOM references

Cisco AI BOM and agent-bom were reviewed for AI asset taxonomy, relationship, version/provenance and BOM design ideas. AgentGuard emits its own inventory, CycloneDX AI/ML BOM, Agent BOM and provenance-graph contracts and does not require either project as a runtime dependency.

If future changes directly copy or modify third-party source files, preserve applicable original copyright/license headers and NOTICE obligations as required by Apache-2.0.
