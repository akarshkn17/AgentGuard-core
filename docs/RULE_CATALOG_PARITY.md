# Rule Catalog Parity

The scanner **engine code is designed to preserve the existing AgentGuard rule contract** (`id`, analysis type, sources, sinks, barriers, matches, message, remediation, source/sink descriptions and detection logic).

This downloadable refactor includes a tested starter catalog for the rule IDs exercised by the migrated analyzers and demo fixture. It intentionally does not pretend that the architecture refactor itself reviewed and re-certified every historical YAML rule.

Before making a production release from your existing AgentGuard repository, import the canonical rule directory so the package contains the exact rule catalog you already maintain:

```powershell
.\scripts\import-existing-rules.ps1 "C:\path\to\AgentGuard\rules\builtin"
python -m pip install -e .\packages\core
python -m pip install -e .\packages\cli
agentguard rules validate
pytest -q
.\scripts\build-wheels.ps1
```

Linux/macOS:

```bash
./scripts/import-existing-rules.sh /path/to/AgentGuard/rules/builtin
```

## Why this is safer

The rule catalog remains owned by one canonical source rather than being manually forked during a packaging refactor. Core's enrichment layer automatically carries each imported rule's remediation and explanatory metadata into emitted findings.

## Release gate

Do not publish `agentguard-core` until:

1. the canonical catalog has been imported;
2. `agentguard rules validate` passes;
3. regression fixtures for the current scanner pass;
4. the packaged wheel is installed in a clean environment and the fixture scan matches the expected rule IDs.
