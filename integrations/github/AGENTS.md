# GitHub CI Integration — Scoped Codex Instructions

This integration must invoke the same published/local AgentGuard CLI/Core used by developers.

- Do not build a second scanner engine in workflow scripts.
- Upload SARIF and report artifacts without changing finding semantics.
- Keep future SaaS authentication separate from Core. Prefer GitHub OIDC workload identity for future platform upload; static long-lived service tokens are a fallback only.
- Do not push or modify the user's GitHub repository unless explicitly requested.
