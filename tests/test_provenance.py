from __future__ import annotations

import json
from pathlib import Path

from agentguard_core import ScanRequest, generate_provenance_graph, scan
from agentguard_core.inventory import InventoryDiscoverer
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "provenance"
SCHEMA = ROOT / "docs" / "schemas" / "provenance-graph.schema.json"
GOLDEN = ROOT / "tests" / "golden"
LEGACY_SAMPLE = ROOT / "docs" / "samples" / "agentguard-provenance.sample.json"


def _scan_fixture(name: str):
    return scan(
        ScanRequest(
            FIXTURES / name,
            rule_ids={"AIR-EXEC-001"},
            include_skill_analysis=False,
        )
    )


def _node_aliases(graph: dict) -> dict[str, str]:
    return {
        node["id"]: f'{node["kind"]}:{node["subtype"]}:{"<repository>" if node["kind"] == "repository" else node["label"]}'
        for node in graph["nodes"]
    }


def _golden_projection(graph: dict) -> dict:
    aliases = _node_aliases(graph)
    edges = {edge["id"]: edge for edge in graph["edges"]}
    return {
        "schema": graph["schema"],
        "summary": {
            "attack_paths": graph["summary"]["attack_paths"],
            "node_classes": graph["summary"]["node_classes"],
            "relationship_types": graph["summary"]["relationship_types"],
            "relationship_evidence_types": graph["summary"]["relationship_evidence_types"],
        },
        "nodes": sorted(aliases.values()),
        "edges": sorted(
            f'{aliases[edge["source"]]} --{edge["relation"]}'
            f'[{edge["relationship_type"]}|{edge["confidence"]}|{edge["derivation_method"]}]-->'
            f' {aliases[edge["target"]]}'
            for edge in graph["edges"]
        ),
        "attack_paths": [
            {
                "rule_id": path["rule_id"],
                "nodes": [aliases[node_id] for node_id in path["node_ids"]],
                "relations": [edges[edge_id]["relation"] for edge_id in path["edge_ids"]],
                "direct_asset_types": sorted(
                    graph_node["subtype"]
                    for graph_node in graph["nodes"]
                    if graph_node["id"] in path["directly_affected_assets"]
                ),
                "transitive_asset_types": sorted(
                    graph_node["subtype"]
                    for graph_node in graph["nodes"]
                    if graph_node["id"] in path["transitively_affected_assets"]
                ),
            }
            for path in graph["attack_paths"]
        ],
    }


def test_cross_file_finding_attribution_and_real_attack_path():
    result = _scan_fixture("vulnerable_cross_file")
    assert not result.errors
    assert len(result.findings) == 1
    finding = result.findings[0]
    inventory = {entity.entity_id: entity for entity in result.inventory}
    assert [inventory[asset_id].entity_type for asset_id in finding.directly_affected_assets] == ["tool"]
    assert [inventory[asset_id].entity_type for asset_id in finding.transitively_affected_assets] == ["agent"]
    assert finding.attribution["derivation_method"] == "reverse-call-ownership"
    assert finding.attribution["source_symbol_ids"]
    assert finding.attribution["sink_symbol_ids"]
    assert [node.kind for node in finding.evidence] == ["source", "propagator", "propagator", "sink"]
    serialized = result.to_dict()
    assert serialized["contract_version"] == "1.2"
    assert serialized["findings"][0]["directly_affected_assets"] == finding.directly_affected_assets
    assert serialized["findings"][0]["transitively_affected_assets"] == finding.transitively_affected_assets
    assert "code_intelligence" not in serialized

    graph = generate_provenance_graph(result)
    relations = {edge["relation"] for edge in graph["edges"]}
    assert {"IMPLEMENTED_BY", "CALLS", "PASSES_DATA_TO", "RETURNS_TO", "HAS_FINDING", "HAS_EVIDENCE", "EVIDENCE_FLOW"}.issubset(relations)
    assert {node["subtype"] for node in graph["nodes"] if node["kind"] == "code"}.issuperset({"module", "function", "external_call"})
    assert all(edge["source_evidence"] and edge["confidence"] and edge["derivation_method"] for edge in graph["edges"])
    assert {edge["relationship_type"] for edge in graph["edges"]}.issuperset({"explicit/direct", "transitive/derived"})

    path = graph["attack_paths"][0]
    graph_edges = {edge["id"]: edge for edge in graph["edges"]}
    assert len(path["edge_ids"]) == len(path["node_ids"]) - 1
    for index, edge_id in enumerate(path["edge_ids"]):
        edge = graph_edges[edge_id]
        assert edge["source"] == path["node_ids"][index]
        assert edge["target"] == path["node_ids"][index + 1]
    evidence_nodes = {node["id"]: node for node in graph["nodes"] if node["kind"] == "evidence"}
    assert [evidence_nodes[node_id]["subtype"] for node_id in path["evidence_node_ids"]] == ["source", "propagator", "propagator", "sink"]


def test_safe_fixture_has_no_security_path():
    result = _scan_fixture("safe_cross_file")
    assert not result.errors
    assert not result.findings
    graph = generate_provenance_graph(result)
    assert not graph["attack_paths"]
    assert not [edge for edge in graph["edges"] if edge["relation"] == "HAS_FINDING"]


def test_inferred_relationship_preserves_confidence_and_derivation():
    result = _scan_fixture("inferred_cross_file")
    assert len(result.findings) == 1
    assert result.findings[0].attribution["confidence"] == "medium"
    graph = generate_provenance_graph(result)
    inferred_calls = [
        edge
        for edge in graph["edges"]
        if edge["relation"] == "CALLS" and edge["relationship_type"] == "inferred"
    ]
    assert len(inferred_calls) == 1
    assert inferred_calls[0]["confidence"] == "medium"
    assert inferred_calls[0]["derivation_method"] == "unique-suffix"
    assert inferred_calls[0]["source_evidence"][0]["file"] == "app.py"


def test_provenance_graph_validates_against_json_schema():
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    vulnerable_graph = generate_provenance_graph(_scan_fixture("vulnerable_cross_file"))
    Draft202012Validator(schema).validate(vulnerable_graph)
    Draft202012Validator(schema).validate(generate_provenance_graph(_scan_fixture("safe_cross_file")))
    assert all(node["node_class"] for node in vulnerable_graph["nodes"])
    assert all(
        edge["relationship_type"] and edge["confidence"] and edge["derivation_method"] and edge["source_evidence"]
        for edge in vulnerable_graph["edges"]
    )


def test_graph_1_0_schema_remains_compatible_with_pre_milestone_2_sample():
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    sample = json.loads(LEGACY_SAMPLE.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(sample)


def test_provenance_golden_snapshot(monkeypatch):
    # Remove checkout-specific Git identity so the golden projection also works
    # for source archives and forks with a different remote URL.
    monkeypatch.setattr(InventoryDiscoverer, "_repo_identity", lambda self: self.root.name)
    monkeypatch.setattr(InventoryDiscoverer, "_git_cmd", lambda self, args: "")
    for fixture, filename in (
        ("vulnerable_cross_file", "provenance-vulnerable.golden.json"),
        ("safe_cross_file", "provenance-safe.golden.json"),
    ):
        graph = generate_provenance_graph(_scan_fixture(fixture))
        expected = json.loads((GOLDEN / filename).read_text(encoding="utf-8"))
        assert _golden_projection(graph) == expected
