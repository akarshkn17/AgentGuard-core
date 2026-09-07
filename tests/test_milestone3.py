from __future__ import annotations

import json
from pathlib import Path

from agentguard_cli.cli import app
from agentguard_core import (
    OSVVulnerabilityProvider,
    ScanRequest,
    VulnerabilityProvider,
    VulnerabilityRecord,
    generate_agent_bom,
    generate_agent_bom_v2,
    generate_cyclonedx,
    generate_provenance_graph,
    scan,
)
from agentguard_core.package_inventory import PackageInventory
from jsonschema import Draft202012Validator
from typer.testing import CliRunner

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "milestone3"
AGENT_BOM_SCHEMA = ROOT / "docs" / "schemas" / "agent-bom-v3.schema.json"
PROVENANCE_SCHEMA = ROOT / "docs" / "schemas" / "provenance-graph.schema.json"


class FakeVulnerabilityProvider(VulnerabilityProvider):
    name = "fixture-provider"

    def __init__(self):
        self.calls = 0
        self.queried_purls: list[str] = []

    def query_batch(self, packages):
        self.calls += 1
        self.queried_purls.extend(package.purl for package in packages)
        result = {package.package_id: [] for package in packages}
        package = next((item for item in packages if item.normalized_name == "langchain-openai"), None)
        if package:
            result[package.package_id] = [VulnerabilityRecord(
                "VULN-FIXTURE-LANGCHAIN",
                "OSV-FIXTURE-001",
                ["CVE-2099-0001", "GHSA-FIXTURE"],
                self.name,
                "high",
                package.package_id,
                "affected",
                "unknown",
                "unknown",
                "present",
                [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                ["CWE-78"],
                [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.3.2"}]}],
                ["0.3.2"],
                ["https://osv.dev/vulnerability/OSV-FIXTURE-001"],
                "2099-01-01T00:00:00Z",
                "2099-01-02T00:00:00Z",
                "2099-01-03T00:00:00Z",
                "Fixture model-wrapper vulnerability",
                "A deterministic test vulnerability.",
                package.version,
            )]
        return result


def _inventory_scan():
    return scan(ScanRequest(
        FIXTURES / "full_project",
        rule_ids={"__inventory_only__"},
        include_skill_analysis=False,
    ))


def test_model_and_package_inventory_prefers_lockfiles_and_keeps_identity_separate():
    result = _inventory_scan()
    assert not result.errors
    packages = {(package.ecosystem, package.normalized_name): package for package in result.packages}
    assert packages[("PyPI", "langchain-openai")].version == "0.3.1"
    assert packages[("PyPI", "langchain-openai")].requested_version == ">=0.2"
    assert packages[("PyPI", "langchain-openai")].dependency_type == "direct"
    assert packages[("PyPI", "openai")].dependency_type == "transitive"
    assert packages[("PyPI", "httpx")].dependency_path == [
        packages[("PyPI", "langchain-openai")].package_id,
        packages[("PyPI", "openai")].package_id,
        packages[("PyPI", "httpx")].package_id,
    ]
    assert packages[("npm", "express")].version == "4.21.1"
    assert packages[("npm", "accepts")].dependency_type == "transitive"
    assert packages[("PyPI", "requests")].licenses == ["Apache-2.0"]
    assert all(package.purl.startswith("pkg:") for package in result.packages)

    models = {model.model_identifier: model for model in result.models}
    remote = models["gpt-4o-mini"]
    assert remote.provider == "openai"
    assert remote.model_revision == ""
    assert remote.configuration_source == "environment_default"
    assert remote.parameters["temperature"] == 0
    assert remote.endpoint_service == "https://models.example.test/v1"
    assert remote.framework_package_version == "0.3.1"
    local = models["acme/support-model"]
    assert local.provider == "huggingface"
    assert local.access_type == "downloaded"
    assert local.repository == "acme/support-model"
    assert local.repository_revision == "4f01c2a"
    assert local.content_revision == ""
    assert local.model_identifier != local.repository_revision
    remote_asset = next(item for item in result.inventory if item.entity_id == remote.model_id)
    local_asset = next(item for item in result.inventory if item.entity_id == local.model_id)
    assert (remote_asset.version, remote_asset.version_source, remote_asset.version_scheme) == ("unknown", "unknown", "unknown")
    assert local_asset.version == "4f01c2a"
    assert models["customer-chat"].provider == "azure-openai"
    assert models["customer-chat"].deployment_name == "customer-chat"
    assert models["claude-3-7-sonnet"].provider == "anthropic"
    assert models["anthropic.claude-v2"].provider == "aws-bedrock"
    assert models["gemini-2.0-flash"].provider == "google"
    assert models["gpt-4.1-mini"].provider == "openai"

    relations = {relationship.relation for relationship in result.relationships}
    assert {
        "AGENT_USES_MODEL",
        "TOOL_USES_MODEL",
        "MODEL_ACCESSED_VIA",
        "MODEL_IMPLEMENTED_WITH_PACKAGE",
        "IMPORTS_PACKAGE",
        "DEPENDS_ON",
    }.issubset(relations)


def test_agent_bom_v3_schema_and_v2_compatibility():
    result = _inventory_scan()
    bom = generate_agent_bom(result)
    assert bom["schema"] == "agentguard-agent-bom/3.0"
    assert bom["summary"]["models"] == 7
    assert bom["summary"]["packages"] == 8
    assert {
        "agents",
        "models",
        "tools",
        "skills",
        "mcp_components",
        "data_retrieval_assets",
        "memory",
        "packages",
        "vulnerabilities",
        "static_findings",
        "relationships",
        "versions",
    }.issubset(bom)
    schema = json.loads(AGENT_BOM_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(bom)
    assert generate_agent_bom_v2(result)["schema"] == "agentguard-agent-bom/2.0"


def test_opt_in_vulnerability_enrichment_is_cached_and_does_not_claim_reachability(tmp_path: Path):
    provider = FakeVulnerabilityProvider()
    cache = tmp_path / "osv-cache.json"
    request = ScanRequest(
        FIXTURES / "full_project",
        rule_ids={"__inventory_only__"},
        include_skill_analysis=False,
        allow_network_enrichment=True,
        vulnerability_cache_path=cache,
        vulnerability_provider=provider,
    )
    first = scan(request)
    second = scan(request)
    assert not first.errors
    assert not second.errors
    assert provider.calls == 1
    assert provider.queried_purls and all(value.startswith("pkg:") for value in provider.queried_purls)
    assert len(first.vulnerabilities) == 1
    vulnerability = first.vulnerabilities[0]
    assert vulnerability.affected_version_status == "affected"
    assert vulnerability.reachability == "unknown"
    assert vulnerability.exploitability == "unknown"
    package = next(item for item in first.packages if item.package_id == vulnerability.affected_package_id)
    assert package.vulnerability_status == "affected"
    assert vulnerability.affected_version == package.version
    cached_text = cache.read_text(encoding="utf-8")
    assert "app.py" not in cached_text
    assert package.purl in cached_text

    serialized = first.to_dict()
    assert serialized["models"]
    assert serialized["packages"]
    assert serialized["vulnerabilities"][0]["vulnerability_id"] == vulnerability.vulnerability_id
    bom_schema = json.loads(AGENT_BOM_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator(bom_schema).validate(generate_agent_bom(first))

    graph = generate_provenance_graph(first)
    graph_schema = json.loads(PROVENANCE_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator(graph_schema).validate(graph)
    vulnerability_node = next(node for node in graph["nodes"] if node["subtype"] == "known_vulnerability")
    assert vulnerability_node["id"] == vulnerability.vulnerability_id
    path = next(item for item in graph["attack_paths"] if item["finding_id"] == vulnerability.vulnerability_id)
    graph_edges = {edge["id"]: edge for edge in graph["edges"]}
    assert len(path["edge_ids"]) == len(path["node_ids"]) - 1
    for index, edge_id in enumerate(path["edge_ids"]):
        assert graph_edges[edge_id]["source"] == path["node_ids"][index]
        assert graph_edges[edge_id]["target"] == path["node_ids"][index + 1]
    assert graph_edges[path["edge_ids"][0]]["relation"] == "AGENT_USES_MODEL"
    assert graph_edges[path["edge_ids"][-1]]["relation"] == "HAS_VULNERABILITY"
    assert path["attribution"]["reachability"] == "unknown"


def test_osv_provider_batches_only_package_identity(monkeypatch):
    package = next(item for item in _inventory_scan().packages if item.normalized_name == "requests")
    captured = {}
    response_document = {
        "results": [{
            "vulns": [{
                "id": "GHSA-TEST-0001",
                "aliases": ["CVE-2099-0002"],
                "summary": "Fixture advisory",
                "details": "Fixture details",
                "published": "2099-01-01T00:00:00Z",
                "modified": "2099-01-02T00:00:00Z",
                "database_specific": {"severity": "MODERATE", "cwe_ids": ["CWE-79"]},
                "affected": [{
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "2.32.4"}],
                    }],
                }],
                "references": [{"url": "https://osv.dev/vulnerability/GHSA-TEST-0001"}],
            }],
        }],
    }

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps(response_document).encode()

    def fake_urlopen(request, timeout):
        captured["payload"] = json.loads(request.data)
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr("agentguard_core.vulnerabilities.urllib.request.urlopen", fake_urlopen)
    records = OSVVulnerabilityProvider(timeout_seconds=3).query_batch([package])[package.package_id]
    assert captured["payload"] == {"queries": [{"package": {"purl": package.purl}}]}
    assert captured["timeout"] == 3
    assert records[0].canonical_id == "GHSA-TEST-0001"
    assert records[0].affected_version == package.version
    assert records[0].affected_version_status == "affected"
    assert records[0].reachability == "unknown"
    assert records[0].fixed_versions == ["2.32.4"]
    assert records[0].cwe == ["CWE-79"]


def test_default_scan_is_offline_and_unresolved_versions_are_not_queried(tmp_path: Path):
    provider = FakeVulnerabilityProvider()
    offline = scan(ScanRequest(
        FIXTURES / "safe_unresolved",
        rule_ids={"__inventory_only__"},
        include_skill_analysis=False,
        vulnerability_provider=provider,
    ))
    assert provider.calls == 0
    assert not offline.vulnerabilities

    online = scan(ScanRequest(
        FIXTURES / "safe_unresolved",
        rule_ids={"__inventory_only__"},
        include_skill_analysis=False,
        allow_network_enrichment=True,
        vulnerability_cache_path=tmp_path / "cache.json",
        vulnerability_provider=provider,
    ))
    assert provider.calls == 0
    assert not online.vulnerabilities
    assert online.packages[0].vulnerability_status == "unknown"


def test_cyclonedx_17_validates_with_official_bundled_schema():
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    result = _inventory_scan()
    provider = FakeVulnerabilityProvider()
    result.vulnerabilities = provider.query_batch(result.packages)[
        next(package.package_id for package in result.packages if package.normalized_name == "langchain-openai")
    ]
    document = generate_cyclonedx(result)
    assert any(component.get("purl") for component in document["components"])
    assert any(component["type"] == "machine-learning-model" for component in document["components"])
    remote_model_component = next(
        component
        for component in document["components"]
        if any(
            prop["name"] == "agentguard:model:identifier" and prop["value"] == "gpt-4o-mini"
            for prop in component.get("properties", [])
        )
    )
    assert remote_model_component["version"] == "unknown"
    assert document["vulnerabilities"][0]["affects"][0]["ref"]
    validation_errors = JsonStrictValidator(SchemaVersion.V1_7).validate_str(json.dumps(document))
    assert not validation_errors, validation_errors


def test_additional_python_and_javascript_lockfile_formats(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.poetry.dependencies]\npython="^3.11"\nfastapi="^0.115"\n',
        encoding="utf-8",
    )
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname="fastapi"\nversion="0.115.6"\n[package.dependencies]\npydantic=">=2"\n'
        '[[package]]\nname="pydantic"\nversion="2.10.4"\n',
        encoding="utf-8",
    )
    (tmp_path / "Pipfile.lock").write_text(
        json.dumps({"default": {"urllib3": {"version": "==2.2.3"}}}),
        encoding="utf-8",
    )
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"lodash": "^4.17.0"}}),
        encoding="utf-8",
    )
    (tmp_path / "yarn.lock").write_text(
        'lodash@^4.17.0:\n  version "4.17.21"\n',
        encoding="utf-8",
    )
    (tmp_path / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\npackages:\n  /chalk@5.3.0: {}\n",
        encoding="utf-8",
    )
    packages, relationships = PackageInventory(tmp_path).discover()
    versions = {(item.ecosystem, item.normalized_name): item.version for item in packages}
    assert versions[("PyPI", "fastapi")] == "0.115.6"
    assert versions[("PyPI", "pydantic")] == "2.10.4"
    assert versions[("PyPI", "urllib3")] == "2.2.3"
    assert versions[("npm", "lodash")] == "4.17.21"
    assert versions[("npm", "chalk")] == "5.3.0"
    assert any(item.relation == "DEPENDS_ON" for item in relationships)


def test_cli_defaults_to_agent_bom_v3_and_keeps_v2_option(tmp_path: Path):
    runner = CliRunner()
    v3_path = tmp_path / "agent-bom-v3.json"
    v2_path = tmp_path / "agent-bom-v2.json"
    v3 = runner.invoke(app, [
        "bom",
        str(FIXTURES / "full_project"),
        "--kind",
        "agent-bom",
        "--output",
        str(v3_path),
    ])
    v2 = runner.invoke(app, [
        "bom",
        str(FIXTURES / "full_project"),
        "--kind",
        "agent-bom",
        "--schema-version",
        "2.0",
        "--output",
        str(v2_path),
    ])
    assert v3.exit_code == 0, v3.output
    assert v2.exit_code == 0, v2.output
    assert json.loads(v3_path.read_text(encoding="utf-8"))["schema"] == "agentguard-agent-bom/3.0"
    assert json.loads(v2_path.read_text(encoding="utf-8"))["schema"] == "agentguard-agent-bom/2.0"
    assert isinstance(
        json.loads(v3_path.read_text(encoding="utf-8"))["static_findings"], list
    )
    assert "--vuln-enrichment" in runner.invoke(app, ["scan", "--help"]).output
