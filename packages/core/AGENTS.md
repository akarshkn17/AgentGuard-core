# AgentGuard Core — Scoped Codex Instructions

This directory is the security engine. Follow the root `AGENTS.md` first.

- Keep Core persistence-free and authentication-free.
- New detectors belong in Core, not the CLI.
- Prefer AST, semantic structure, control/data-flow, and taint analysis over broad regex matching when the vulnerability semantics require it.
- Rules and analyzers are not the same thing: preserve catalog metadata while implementing detector logic independently.
- Every detector change requires positive and negative regression fixtures.
- Findings must include useful evidence and be enrichable with description/remediation.
- Inventory discovery must return stable logical identities, explicit human/component versions where discoverable, framework/package versions separately, and content hashes only as integrity metadata.
- Provenance relationships need file/line/symbol evidence whenever resolution is available.
- Do not add FastAPI, database, auth, tenancy, UI, or GitHub Actions concerns here.
