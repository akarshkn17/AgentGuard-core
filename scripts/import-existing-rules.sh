#!/usr/bin/env bash
set -euo pipefail
SOURCE_RULES="${1:?Usage: import-existing-rules.sh /path/to/AgentGuard/rules/builtin}"
DEST="$(cd "$(dirname "$0")/.." && pwd)/packages/core/src/agentguard_core/rules/builtin"
rm -f "$DEST"/*.yaml
cp "$SOURCE_RULES"/*.yaml "$DEST"/
echo "Imported canonical AgentGuard rules into $DEST"
PYTHONPATH="$(cd "$(dirname "$0")/.." && pwd)/packages/core/src" python - <<PY
from pathlib import Path
from agentguard_core.rules import RuleStore
p=Path(r"$DEST")
s=RuleStore(p)
print("rules:", len(s.load()), "validation errors:", s.validate())
PY
