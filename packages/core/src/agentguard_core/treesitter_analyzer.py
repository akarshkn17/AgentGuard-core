from __future__ import annotations

from pathlib import Path

from .models import EvidenceNode, Finding
from .rules import Rule


class TreeSitterAnalyzer:
    """Optional JS/TS AST adapter preserved from AgentGuard's current design."""

    def __init__(self, path: Path, text: str, rules: list[Rule]):
        self.path = path
        self.text = text
        self.rules = rules
        self.lines = text.splitlines()

    def _text(self, node, raw: bytes) -> str:
        return raw[node.start_byte:node.end_byte].decode("utf-8", "ignore")

    def analyze(self) -> list[Finding]:
        try:
            from tree_sitter_language_pack import get_parser
        except Exception:
            return []
        lang = "typescript" if self.path.suffix.lower() in (".ts", ".tsx") else "javascript"
        try:
            tree = get_parser(lang).parse(self.text.encode())
        except Exception:
            return []
        raw = self.text.encode()
        calls = []
        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            stack.extend(reversed(node.children))
            if node.type == "call_expression":
                fn = node.child_by_field_name("function")
                args = node.child_by_field_name("arguments")
                calls.append((node, self._text(fn, raw) if fn else "", self._text(args, raw) if args else ""))
        out: list[Finding] = []
        by_id = {rule.id: rule for rule in self.rules}
        for node, fn, args in calls:
            line = node.start_point[0] + 1
            code = self.lines[line - 1].strip() if line <= len(self.lines) else ""
            checks: list[tuple[str, str]] = []
            if fn.endswith(".exec") or fn.endswith("execSync") or fn.endswith(".spawn"):
                checks.append(("AIR-EXEC-001", "process execution"))
            if fn in ("eval", "Function") or fn.endswith(".runInContext") or fn.endswith(".runInNewContext"):
                checks.append(("AIR-EXEC-002", "dynamic code execution"))
            if fn.startswith("fetch") or "axios." in fn or "http." in fn or "https." in fn:
                if "rejectUnauthorized: false" in args or "rejectUnauthorized:false" in args:
                    checks.append(("AIR-NET-004", "TLS verification disabled"))
            for rule_id, label in checks:
                rule = by_id.get(rule_id)
                if rule:
                    out.append(
                        Finding(
                            rule.id, rule.name, rule.severity.title(), str(self.path), line,
                            rule.message or rule.name,
                            [EvidenceNode("structural", label, str(self.path), line, fn, code)],
                            code, rule.analysis.type,
                        ).finalize()
                    )
        return list({finding.fingerprint: finding for finding in out}.values())
