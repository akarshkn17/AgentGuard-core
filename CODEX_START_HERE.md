# Start AgentGuard Development in Codex

Open Codex with this repository as the working directory. Codex should automatically load the root `AGENTS.md` project instructions.

For the first session, use this prompt:

> Read `AGENTS.md`, `docs/CODEX_PROJECT_CONTEXT.md`, `docs/CODEX_NEXT_WORK.md`, `RULE_COVERAGE.json`, and `BUILD_VALIDATION.md`. Inspect the current source and tests. Do not modify anything yet. First give me: (1) your understanding of the architecture, (2) exact current rule/detector status, (3) the top 10 scanner-quality gaps you would address next, and (4) a proposed implementation sequence that preserves Core/CLI boundaries. Do not commit or push anything.

After Codex confirms the current state, a useful implementation prompt is:

> Start the next scanner-quality milestone. Work rule-by-rule on the semantic/control-flow rules that are not deeply implemented. For each rule, add a vulnerable fixture, a safe fixture, implement the correct AST/taint/control-flow detector, verify evidence quality, run tests, and update `RULE_COVERAGE.json` only after the tests prove the detector. Preserve all 181 catalog rules and do not work on SaaS/UI/authentication yet. Do not commit or push.

## Local Windows start

From PowerShell, change to the extracted project directory and start the Codex CLI/app from that repository root. Keeping the working directory at the repository root ensures project `AGENTS.md` guidance is discovered.

If you use Codex across many unrelated projects, put only personal/general preferences in `~/.codex/AGENTS.md`. Keep AgentGuard-specific context in this repository so it travels with the code and does not affect other projects.
