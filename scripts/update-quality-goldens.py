from __future__ import annotations

import json
import runpy
from pathlib import Path

from agentguard_core import ScanRequest, scan
from agentguard_core.inventory import InventoryDiscoverer

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests" / "golden"


def main() -> None:
    namespace = runpy.run_path(str(ROOT / "tests" / "test_milestone4.py"))
    InventoryDiscoverer._repo_identity = lambda self: self.root.name
    InventoryDiscoverer._git_cmd = lambda self, args: ""
    result = scan(ScanRequest(
        ROOT / "tests" / "fixtures" / "milestone3" / "full_project",
        rule_ids={"__inventory_only__"},
        include_skill_analysis=False,
    ))
    documents = {
        "agent-bom-v3.golden.json": namespace["_bom_projection"](result),
        "cyclonedx-1.7.golden.json": namespace["_cyclonedx_projection"](result),
    }
    GOLDEN.mkdir(parents=True, exist_ok=True)
    for filename, document in documents.items():
        (GOLDEN / filename).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
