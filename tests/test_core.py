import json
from pathlib import Path

from agentguard_core import (
    ScanRequest,
    generate_agent_bom,
    generate_agent_bom_v2,
    generate_cyclonedx,
    generate_provenance_graph,
    scan,
)
from agentguard_core.exporters import csv_findings, junit_xml, sarif
from agentguard_core.reporting import detailed_html, summary_html
from agentguard_core.rules import RuleStore
from agentguard_core.scanner import bundled_rules_dir

ROOT = Path(__file__).resolve().parents[1]


def test_catalog_is_complete_from_risk_workbook():
    rules = RuleStore(bundled_rules_dir()).load()
    assert len(rules) == 181
    assert sum(r.engine == "agentguard" for r in rules) == 113
    assert sum(r.engine == "agentguard-skill" for r in rules) == 68
    assert not RuleStore(bundled_rules_dir()).validate()


def test_vulnerable_fixture_has_enriched_findings():
    result = scan(ROOT / "examples" / "vulnerable_agent")
    assert not result.errors
    by_rule = {finding.rule_id: finding for finding in result.findings}
    assert "AIR-EXEC-001" in by_rule
    assert "AIR-NET-001" in by_rule
    finding = by_rule["AIR-EXEC-001"]
    assert finding.finding_id.startswith("AGF-")
    assert finding.finding_id == "AGF-8952818A1745751CE61A4A4E"
    assert finding.description
    assert finding.remediation
    assert finding.file == "app.py"
    assert any(node.kind == "source" for node in finding.evidence)
    assert any(node.kind == "sink" for node in finding.evidence)


def test_native_skill_engine_runs_without_external_skillspector():
    result = scan(ROOT / "examples" / "vulnerable_skill")
    ids = {finding.rule_id for finding in result.findings}
    ids.update(
        related["rule_id"]
        for finding in result.findings
        for related in finding.engine_metadata.get("related_rules", [])
    )
    assert {"NVS-AR1", "NVS-AR3", "NVS-P1", "NVS-PE3", "NVS-AST1", "NVS-AST4", "NVS-LP2"}.issubset(ids)
    assert all(f.engine_metadata.get("engine") != "skillspector-subprocess" for f in result.findings if f.rule_id.startswith("NVS-"))


def test_exporters_are_self_contained():
    result = scan(ROOT / "examples" / "vulnerable_agent")
    assert sarif(result)["version"] == "2.1.0"
    assert "finding_id" in csv_findings(result)
    assert "testsuite" in junit_xml(result)
    assert "Remediation" in detailed_html(result)
    assert "AgentGuard Scan Summary" in summary_html(result)
    assert generate_cyclonedx(result)["bomFormat"] == "CycloneDX"
    assert generate_agent_bom(result)["schema"] == "agentguard-agent-bom/3.0"
    assert generate_agent_bom_v2(result)["schema"] == "agentguard-agent-bom/2.0"
    assert generate_provenance_graph(result)["schema"] == "agentguard-provenance-graph/1.0"
    json.dumps(result.to_dict())


def test_inventory_has_distinct_component_and_framework_versions(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="demo"\nversion="1.7.0"\ndependencies=["langchain==0.9.9"]\n',
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        'from langchain.agents import Agent\n'
        'agent = Agent(name="demo-agent", version="2.3.0")\n',
        encoding="utf-8",
    )
    result = scan(ScanRequest(tmp_path, rule_ids={"__inventory_only__"}))
    agent = next(item for item in result.inventory if item.entity_type == "agent")
    assert agent.category == "agentic"
    assert agent.package_name == "langchain"
    assert agent.framework_version == "==0.9.9"
    assert agent.version == "2.3.0"
    assert agent.version_source == "constructor"
    assert agent.version_id.startswith("AGV-")
    assert agent.entity_id.startswith("AGENT-")
    assert agent.version_id != agent.entity_id


def test_agent_bom_and_graph_are_rich():
    result = scan(ROOT / "examples" / "multi_agent_demo")
    bom = generate_agent_bom(result)
    assert bom["summary"]["agents"] == 1
    agent = bom["agents"][0]
    assert agent["name"] == "support-agent"
    assert agent["version"]["value"] == "2.1.0"
    assert agent["agent_id"].startswith("AGENT-")
    assert agent["agent_version_id"].startswith("AGV-")
    # A Git checkout uses its remote URL as repository identity, while an
    # unpacked source archive falls back to the scan-root name. Both must be
    # deterministic within the same repository context.
    repeated_agent = generate_agent_bom(
        scan(ROOT / "examples" / "multi_agent_demo")
    )["agents"][0]
    assert repeated_agent["agent_id"] == agent["agent_id"]
    assert repeated_agent["agent_version_id"] == agent["agent_version_id"]
    relations = {(d["relation"], d["type"]) for d in agent["dependencies"]}
    assert ("USES_MODEL", "model") in relations
    assert ("USES_TOOL", "tool") in relations
    assert ("USES_SKILL", "skill") in relations
    graph = generate_provenance_graph(result)
    assert graph["summary"]["nodes"] > len(result.inventory)
    assert graph["summary"]["attack_paths"] == len(result.findings)
    assert any(edge["relation"] == "HAS_FINDING" for edge in graph["edges"])
