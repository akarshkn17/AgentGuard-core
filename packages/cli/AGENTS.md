# AgentGuard CLI — Scoped Codex Instructions

This directory is a thin developer adapter over `agentguard-core`. Follow the root `AGENTS.md` first.

- Do not reimplement scanning logic in the CLI.
- CLI parses arguments, invokes Core, renders/writes outputs, and applies exit/fail thresholds.
- Keep local scanning authentication-free.
- Preserve machine-readable formats for CI: JSON, SARIF, JUnit, CSV, graph/BOM outputs.
- Keep commands and error behavior scriptable on Windows PowerShell and Linux shells.
