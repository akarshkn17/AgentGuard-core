# Finding Contract v1.1

Every normalized finding now contains scanner evidence **and** the rule explanation required by developers.

Key fields:

| Field | Purpose |
|---|---|
| `finding_id` | Stable external ID (`AGF-...`) derived from the semantic fingerprint |
| `fingerprint` | Stable, line-number-independent identity used for deduplication/baselining |
| `rule_id` | Canonical AgentGuard rule identifier |
| `title` / `description` | Human-readable finding and risk explanation |
| `severity` / `category` | Priority and taxonomy |
| `analysis_type` | taint/config/structural/etc. |
| `location` | repository-relative file and line |
| `evidence` | deterministic source/propagator/sink or structural/config path |
| `source_description` | what the rule treats as the risky source |
| `sink_description` | what dangerous action/configuration is reached |
| `detection_logic` | concise explanation of how the rule detects the condition |
| `remediation` | ordered, actionable remediation steps |
| `mappings` / `cwe` | optional control/taxonomy mappings |
| `engine_metadata` | engine and resolution metadata |

The scanner still detects issues using the existing analyzers. `enrichment.py` joins the emitted `rule_id` to the rule catalog after detection and copies the descriptive/remediation metadata into the finding. This separation means remediation quality can improve without changing data-flow logic.

## Example shape

```json
{
  "finding_id": "AGF-8952818A1745751CE61A4A4E",
  "rule_id": "AIR-EXEC-001",
  "title": "LLM or user input reaches shell command execution",
  "severity": "Critical",
  "category": "Code Execution",
  "description": "Model output ... can influence an operating-system command.",
  "location": {"file": "app.py", "line": 11},
  "remediation": [
    "Avoid shell=True and shell command string interpolation.",
    "Use fixed executables with argument arrays and strict allowlists."
  ],
  "evidence": [
    {"kind": "source", "label": "llm_output", "file": "app.py", "line": 17},
    {"kind": "sink", "label": "shell_execution", "file": "app.py", "line": 11}
  ]
}
```
