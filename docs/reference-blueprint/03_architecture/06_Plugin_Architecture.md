# External Scanner Plugin Architecture

## Goal
Add or replace security engines without changing AgentGuard Core or hard-coding vendor payloads into the UI.

## Adapter contract
Every engine implements a small interface:

```text
metadata() -> engine identity/capabilities
prepare(job, workspace, credentials)
execute() -> vendor/native raw result
normalize(raw) -> EngineResult
cleanup()
```

## EngineResult
The normalized result can contain:
- canonical findings
- inventory entities
- relationships
- artifacts
- engine errors/warnings
- coverage/scan metrics

## Credential model
- engine credentials are owned by the Platform integration configuration;
- secret values live in Key Vault, not PostgreSQL;
- the worker receives only credentials required for that job/engine;
- plugin code cannot enumerate unrelated integration credentials.

## Failure model
An external engine failure can make a scan `partial` without destroying successful native AgentGuard results. The result records engine-level state so lifecycle resolution can avoid false closure.

See `diagrams/09_plugin_architecture.drawio`.
