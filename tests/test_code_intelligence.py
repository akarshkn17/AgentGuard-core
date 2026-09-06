from __future__ import annotations

from pathlib import Path

from agentguard_core import ScanRequest, scan
from agentguard_core.code_intelligence import (
    CodeIntelligenceSession,
    ResolutionConfidence,
    SanitizerRegistry,
    SanitizerState,
    SymbolKind,
)
from agentguard_core.project_analyzer import ProjectPythonAnalyzer
from agentguard_core.rules import RuleStore
from agentguard_core.scanner import bundled_rules_dir

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "code_intelligence"


def _write(root: Path, relative: str, source: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return path


def _scan_exec(root: Path):
    return scan(
        ScanRequest(
            root,
            rule_ids={"AIR-EXEC-001"},
            include_inventory=False,
            include_skill_analysis=False,
            enable_tree_sitter=False,
        )
    )


def test_symbol_index_records_ranges_decorators_methods_and_nested_functions(tmp_path: Path):
    path = _write(
        tmp_path,
        "app.py",
        "def tool(fn):\n    return fn\n\n"
        "class Worker:\n"
        "    @tool\n"
        "    def run(self, command):\n"
        "        def nested(value):\n"
        "            return value\n"
        "        return nested(command)\n",
    )
    session = CodeIntelligenceSession.from_files(tmp_path, [path])

    assert session.index.symbols["app.Worker"].kind is SymbolKind.CLASS
    method = session.index.symbols["app.Worker.run"]
    nested = session.index.symbols["app.Worker.run.nested"]
    assert method.kind is SymbolKind.METHOD
    assert method.parameters == ("self", "command")
    assert method.decorators == ("app.tool",)
    assert method.source_range.start.line == 5
    assert method.source_range.end.line == 9
    assert nested.kind is SymbolKind.NESTED_FUNCTION
    assert nested.parent_symbol_id == method.symbol_id
    assert session.index.containing_symbol(path, 7, 12).symbol_id == nested.symbol_id


def test_call_resolution_tracks_import_alias_method_and_confidence(tmp_path: Path):
    first = _write(tmp_path, "helpers.py", "def execute(value):\n    return value\n")
    second = _write(
        tmp_path,
        "app.py",
        "from helpers import execute as run_helper\n\n"
        "class Worker:\n"
        "    def handle(self, value):\n"
        "        return run_helper(value)\n\n"
        "def dispatch(value):\n"
        "    worker = Worker()\n"
        "    return worker.handle(value)\n",
    )
    session = CodeIntelligenceSession.from_files(tmp_path, [first, second])
    targets = {
        session.index.symbols_by_id[edge.callee_symbol_id].qualified_name
        for edge in session.call_edges
    }
    assert {"helpers.execute", "app.Worker.handle"}.issubset(targets)
    assert all(edge.confidence in {ResolutionConfidence.EXACT, ResolutionConfidence.MEDIUM} for edge in session.call_edges)


def test_fake_sanitizer_name_does_not_clear_taint(tmp_path: Path):
    result = _scan_exec(FIXTURES / "edge_fake_sanitizer_recursion")
    finding = next(item for item in result.findings if item.rule_id == "AIR-EXEC-001")
    assert any(node.kind == "sanitizer" and "unverified" in node.label for node in finding.evidence)
    assert finding.engine_metadata["containing_symbol"] == "app.run"


def test_structurally_proven_allowlist_clears_applicable_taint(tmp_path: Path):
    fixture = FIXTURES / "safe_allowlist"
    result = _scan_exec(fixture)
    assert not [item for item in result.findings if item.rule_id == "AIR-EXEC-001"]
    function = CodeIntelligenceSession.from_files(fixture, [fixture / "app.py"]).index.functions["app.require_allowed"]
    sanitizer = SanitizerRegistry().evaluate("app.require_allowed", function)
    assert sanitizer.state is SanitizerState.PROVEN


def test_attribute_and_container_taint_crosses_resolved_method_calls(tmp_path: Path):
    fixture = FIXTURES / "vulnerable_attribute_container"
    path = fixture / "app.py"
    rules = [rule for rule in RuleStore(bundled_rules_dir()).load() if rule.id == "AIR-EXEC-001"]
    session = CodeIntelligenceSession.from_files(fixture, [path])
    findings = ProjectPythonAnalyzer.from_files(fixture, [path], rules, session).analyze()

    finding = next(item for item in findings if item.rule_id == "AIR-EXEC-001")
    assert finding.engine_metadata["containing_symbol"] == "app.Worker.execute"
    assert [node.kind for node in finding.evidence][0] == "source"
    assert [node.kind for node in finding.evidence][-1] == "sink"
    assert any("stored at" in node.label for node in finding.evidence)
    assert any(edge.operation == "argument-to-parameter" for edge in session.data_flow_edges)


def test_clean_container_entry_does_not_inherit_sibling_taint(tmp_path: Path):
    assert not _scan_exec(FIXTURES / "safe_container_entry").findings


def test_recursive_flow_is_bounded_and_retains_evidence(tmp_path: Path):
    result = _scan_exec(FIXTURES / "edge_fake_sanitizer_recursion")
    finding = next(item for item in result.findings if item.rule_id == "AIR-EXEC-001")
    assert len(finding.evidence) <= 64
    assert finding.evidence[0].kind == "source"
    assert finding.evidence[-1].kind == "sink"


def test_cross_file_alias_and_nested_return_preserve_ordered_flow():
    result = _scan_exec(FIXTURES / "vulnerable_cross_file_nested")
    finding = next(item for item in result.findings if item.rule_id == "AIR-EXEC-001")
    labels = [node.label for node in finding.evidence]
    assert any("parameter helpers.forward.value" in label for label in labels)
    assert any("return from helpers.forward" in label for label in labels)
    assert finding.evidence[0].kind == "source"
    assert finding.evidence[-1].kind == "sink"


def test_fingerprints_are_deterministic_across_repeated_scans():
    fixture = FIXTURES / "vulnerable_cross_file_nested"
    first = [(item.rule_id, item.finding_id, item.fingerprint) for item in _scan_exec(fixture).findings]
    second = [(item.rule_id, item.finding_id, item.fingerprint) for item in _scan_exec(fixture).findings]
    assert first == second


def test_parse_errors_are_visible_once_in_scan_result(tmp_path: Path):
    _write(tmp_path, "broken.py", "def broken(:\n    pass\n")
    result = _scan_exec(tmp_path)
    parser_errors = [error for error in result.errors if error.stage == "python-parser"]
    assert len(parser_errors) == 1
    assert result.scan.status == "completed_with_errors"


def test_partial_sanitizer_retains_taint_and_evidence():
    result = _scan_exec(FIXTURES / "edge_partial_sanitizer")
    finding = next(item for item in result.findings if item.rule_id == "AIR-EXEC-001")
    assert any(node.kind == "sanitizer" and "partial" in node.label for node in finding.evidence)


def test_builtin_proven_numeric_sanitizer_is_sink_aware():
    result = _scan_exec(FIXTURES / "safe_numeric_sanitizer")
    assert not [item for item in result.findings if item.rule_id == "AIR-EXEC-001"]
