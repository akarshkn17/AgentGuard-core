# Core / CLI Release Checklist

1. Import the current canonical AgentGuard rules (`scripts/import-existing-rules.*`).
2. Run `agentguard rules validate`.
3. Run `pytest -q`.
4. Run the vulnerable fixture and review both HTML reports.
5. Build wheels with `scripts/build-wheels.*`.
6. Install both wheels into a clean Python 3.11+ environment.
7. Run `agentguard version` and `agentguard scan examples/vulnerable_agent --verbose`.
8. Publish `agentguard-core` first.
9. Publish `agentguard-cli` second.
10. Test the published CLI using the GitHub Actions example with `--fail-on none`.
11. Only after baseline triage, enable a blocking severity threshold.

Future SaaS/FastAPI/authentication work is a separate release stream and must not be added as a dependency of Core.
