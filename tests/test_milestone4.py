from __future__ import annotations

import copy
import json
import time
from pathlib import Path

from agentguard_cli.cli import app
from agentguard_core import (
    RuleQualityHarness,
    ScanRequest,
    generate_agent_bom,
    generate_cyclonedx,
    generate_provenance_graph,
    scan,
)
from agentguard_core.inventory import InventoryDiscoverer
from agentguard_core.rules import RuleStore
from agentguard_core.scanner import bundled_rules_dir
from jsonschema import Draft202012Validator
from typer.testing import CliRunner

ROOT = Path(__file__).resolve().parents[1]
COVERAGE = ROOT / "RULE_COVERAGE.json"
COVERAGE_SCHEMA = ROOT / "docs" / "schemas" / "rule-coverage.schema.json"
FIXTURES = ROOT / "tests" / "fixtures"
GOLDEN = ROOT / "tests" / "golden"
VALIDATED_SKILL_RULES = {"NVS-AR1", "NVS-AR3", "NVS-P1", "NVS-PE3", "NVS-AST1", "NVS-AST4", "NVS-LP2"}


def _rules():
    return RuleStore(bundled_rules_dir()).load()


def _stable_repository_identity(monkeypatch) -> None:
    monkeypatch.setattr(InventoryDiscoverer, "_repo_identity", lambda self: self.root.name)
    monkeypatch.setattr(InventoryDiscoverer, "_git_cmd", lambda self, args: "")


def _bom_projection(result) -> dict:
    bom = generate_agent_bom(result)
    return {
        "schema": bom["schema"],
        "summary": bom["summary"],
        "models": sorted([
            {
                "model_id": model["model_id"],
                "provider": model["provider"],
                "identifier": model["model_identifier"],
                "revision": model["model_revision"],
                "configuration_source": model["configuration_source"],
                "framework_package_version": model["framework_package_version"],
            }
            for model in bom["models"]
        ], key=lambda item: (item["provider"], item["identifier"], item["model_id"])),
        "packages": sorted([
            {
                "package_id": package["package_id"],
                "purl": package["purl"],
                "dependency_type": package["dependency_type"],
                "dependency_path": package["dependency_path"],
            }
            for package in bom["packages"]
        ], key=lambda item: item["purl"]),
        "relationships": sorted(
            [item["source_id"], item["relation"], item["target_id"]]
            for item in bom["relationships"]
        ),
        "versions": sorted(
            [item["entity_id"], item["version_id"], item["version"], item["scheme"]]
            for item in bom["versions"]
        ),
    }


def _cyclonedx_projection(result) -> dict:
    document = generate_cyclonedx(result)
    return {
        "bomFormat": document["bomFormat"],
        "specVersion": document["specVersion"],
        "components": sorted([
            {
                "bom-ref": item["bom-ref"],
                "type": item["type"],
                "name": item["name"],
                "version": item["version"],
                "purl": item.get("purl", ""),
            }
            for item in document["components"]
        ], key=lambda item: item["bom-ref"]),
        "dependencies": sorted(document["dependencies"], key=lambda item: item["ref"]),
    }


def test_every_rule_has_schema_valid_quality_tracking():
    document = json.loads(COVERAGE.read_text(encoding="utf-8"))
    schema = json.loads(COVERAGE_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(document)
    harness = RuleQualityHarness.load(COVERAGE, _rules())
    assert not harness.validate()
    report = harness.report()
    assert report["total_rules"] == 181
    assert report["validated_rules"] == 8
    assert report["implementation_statuses"] == {
        "implemented_unvalidated": 135,
        "network_conditional": 2,
        "partially_validated": 1,
        "requires_dedicated_detector": 35,
        "validated": 8,
    }


def test_quality_harness_rejects_unproven_validated_claim():
    document = json.loads(COVERAGE.read_text(encoding="utf-8"))
    altered = copy.deepcopy(document)
    candidate = next(item for item in altered["rules"] if item["implementation_status"] == "implemented_unvalidated")
    candidate["implementation_status"] = "validated"
    candidate["positive_fixtures"] = []
    candidate["negative_fixtures"] = []
    candidate["validation_tests"] = []
    issues = RuleQualityHarness(COVERAGE, altered, _rules()).validate()
    assert any(issue.code == "unproven-validation" and issue.rule_id == candidate["rule_id"] for issue in issues)


def test_validated_skill_rules_resist_false_positive_fixture():
    safe = scan(ScanRequest(
        FIXTURES / "quality" / "skill_false_positive",
        rule_ids=VALIDATED_SKILL_RULES,
        include_inventory=False,
    ))
    assert not safe.errors
    assert not (VALIDATED_SKILL_RULES & {finding.rule_id for finding in safe.findings})

    vulnerable = scan(ScanRequest(
        ROOT / "examples" / "vulnerable_skill",
        rule_ids=VALIDATED_SKILL_RULES,
        include_inventory=False,
    ))
    by_rule = {finding.rule_id: finding for finding in vulnerable.findings}
    assert VALIDATED_SKILL_RULES.issubset(by_rule)
    quality = {item["rule_id"]: item for item in json.loads(COVERAGE.read_text(encoding="utf-8"))["rules"]}
    for rule_id in VALIDATED_SKILL_RULES:
        assert by_rule[rule_id].evidence[0].kind in quality[rule_id]["expected_evidence_shape"]


def test_finding_inventory_entity_and_version_ids_are_deterministic(monkeypatch):
    _stable_repository_identity(monkeypatch)
    request = ScanRequest(
        FIXTURES / "provenance" / "vulnerable_cross_file",
        rule_ids={"AIR-EXEC-001"},
        include_skill_analysis=False,
    )
    first = scan(request)
    second = scan(request)
    assert [(item.finding_id, item.fingerprint) for item in first.findings] == [
        (item.finding_id, item.fingerprint) for item in second.findings
    ]
    assert [(item.entity_id, item.version_id) for item in first.inventory] == [
        (item.entity_id, item.version_id) for item in second.inventory
    ]


def test_agent_bom_and_cyclonedx_semantic_snapshots(monkeypatch):
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    _stable_repository_identity(monkeypatch)
    result = scan(ScanRequest(
        FIXTURES / "milestone3" / "full_project",
        rule_ids={"__inventory_only__"},
        include_skill_analysis=False,
    ))
    expected_bom = json.loads((GOLDEN / "agent-bom-v3.golden.json").read_text(encoding="utf-8"))
    expected_cyclonedx = json.loads((GOLDEN / "cyclonedx-1.7.golden.json").read_text(encoding="utf-8"))
    assert _bom_projection(result) == expected_bom
    assert _cyclonedx_projection(result) == expected_cyclonedx
    errors = JsonStrictValidator(SchemaVersion.V1_7).validate_str(json.dumps(generate_cyclonedx(result)))
    assert not errors, errors


def test_attack_paths_remain_connected_and_analysis_errors_visible(tmp_path: Path):
    result = scan(ScanRequest(
        FIXTURES / "provenance" / "vulnerable_cross_file",
        rule_ids={"AIR-EXEC-001"},
        include_skill_analysis=False,
    ))
    graph = generate_provenance_graph(result)
    edges = {edge["id"]: edge for edge in graph["edges"]}
    for path in graph["attack_paths"]:
        assert len(path["edge_ids"]) == len(path["node_ids"]) - 1
        for index, edge_id in enumerate(path["edge_ids"]):
            assert (edges[edge_id]["source"], edges[edge_id]["target"]) == (
                path["node_ids"][index], path["node_ids"][index + 1]
            )

    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    failed = scan(ScanRequest(tmp_path, rule_ids={"AIR-EXEC-001"}, include_inventory=False, include_skill_analysis=False))
    assert failed.scan.status == "completed_with_errors"
    assert any(error.stage == "python-parser" for error in failed.errors)


def test_complete_offline_scan_has_measured_performance_budget():
    started = time.perf_counter()
    result = scan(FIXTURES / "milestone3" / "full_project")
    elapsed = time.perf_counter() - started
    assert not result.errors
    assert result.metrics.files_scanned >= 5
    assert result.metrics.duration_ms > 0
    assert elapsed < 30.0


def test_quality_cli_validates_and_reports(tmp_path: Path):
    runner = CliRunner()
    validation = runner.invoke(app, ["quality", "validate", "--coverage", str(COVERAGE)])
    report_path = tmp_path / "quality-report.json"
    report = runner.invoke(app, ["quality", "report", "--coverage", str(COVERAGE), "--output", str(report_path)])
    assert validation.exit_code == 0, validation.output
    assert "181 rules" in validation.output
    assert report.exit_code == 0, report.output
    assert json.loads(report_path.read_text(encoding="utf-8"))["validated_rules"] == 8

    malformed_path = tmp_path / "malformed-quality.json"
    malformed_path.write_text("[]", encoding="utf-8")
    malformed = runner.invoke(app, ["quality", "validate", "--coverage", str(malformed_path)])
    assert malformed.exit_code == 2
    assert "Unable to load quality manifest" in malformed.output
