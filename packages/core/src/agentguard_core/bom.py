from __future__ import annotations

import uuid
from collections import Counter, defaultdict
from typing import Any

from .contracts import ENGINE_VERSION, ScanResult

CYCLONEDX_TYPE = {
    "model": "machine-learning-model",
    "embedding": "machine-learning-model",
    "embedding_model": "machine-learning-model",
    "vector_store": "data",
    "dataset": "data",
    "knowledge_base": "data",
    "memory": "data",
    "mcp_resource": "data",
    "mcp_prompt": "data",
    "prompt": "data",
    "agent": "application",
    "sub_agent": "application",
    "orchestrator": "application",
    "agent_proxy": "application",
    "mcp_server": "application",
    "mcp_client": "application",
    "mcp_gateway": "application",
    "llm_endpoint": "application",
    "model_endpoint": "application",
    "deployment": "application",
    "tool": "library",
    "function_tool": "library",
    "mcp_tool": "library",
    "skill": "library",
    "plugin": "library",
    "guardrail": "library",
    "retriever": "library",
    "capability": "library",
    "dependency": "library",
    "package": "library",
}
AGENT_TYPES = {"agent", "sub_agent", "orchestrator", "agent_proxy"}
TOOL_TYPES = {"tool", "function_tool", "mcp_tool"}
SKILL_TYPES = {"skill", "plugin"}
MCP_TYPES = {"mcp_server", "mcp_client", "mcp_gateway", "mcp_tool", "mcp_resource", "mcp_prompt"}
DATA_TYPES = {"vector_store", "retriever", "dataset", "knowledge_base", "feature_store", "rag_pipeline"}
MEMORY_TYPES = {"memory", "checkpoint_store"}


def _version_properties(entity: Any) -> list[dict[str, str]]:
    properties = [
        {"name": "agentguard:identity:entity_id", "value": entity.entity_id},
        {"name": "agentguard:identity:version_id", "value": entity.version_id},
        {"name": "agentguard:version:value", "value": entity.version or "unknown"},
        {"name": "agentguard:version:scheme", "value": entity.version_scheme or "unknown"},
        {"name": "agentguard:version:source", "value": entity.version_source or "unknown"},
    ]
    if entity.framework_version:
        properties.append({"name": "agentguard:framework:version", "value": entity.framework_version})
    if entity.package_version:
        properties.append({"name": "agentguard:package:version", "value": entity.package_version})
    if entity.content_hash:
        properties.append({"name": "agentguard:content:sha256", "value": entity.content_hash})
    return properties


def _cyclonedx_vulnerability(record: Any, packages: dict[str, Any]) -> dict[str, Any]:
    package = packages.get(record.affected_package_id)
    severity = record.severity.lower()
    severity = {"moderate": "medium", "important": "high"}.get(severity, severity)
    value: dict[str, Any] = {
        "bom-ref": record.vulnerability_id,
        "id": record.canonical_id,
        "source": {"name": record.source, "url": "https://osv.dev" if record.source == "OSV" else ""},
        "affects": [{
            "ref": record.affected_package_id,
            "versions": [{"version": record.affected_version or (package.version if package else "unknown"), "status": record.affected_version_status}],
        }],
        "properties": [
            {"name": "agentguard:vulnerability:package-presence", "value": record.package_presence},
            {"name": "agentguard:vulnerability:affected-version", "value": record.affected_version_status},
            {"name": "agentguard:vulnerability:reachability", "value": record.reachability},
            {"name": "agentguard:vulnerability:exploitability", "value": record.exploitability},
            {"name": "agentguard:vulnerability:enriched-at", "value": record.enrichment_timestamp},
        ],
    }
    if record.summary or record.details:
        value["description"] = record.summary or record.details
    if severity in {"unknown", "none", "info", "low", "medium", "high", "critical"}:
        value["ratings"] = [{"source": {"name": record.source}, "severity": severity}]
    if record.cwe:
        cwes = []
        for item in record.cwe:
            try:
                cwes.append(int(str(item).upper().removeprefix("CWE-")))
            except ValueError:
                continue
        if cwes:
            value["cwes"] = sorted(set(cwes))
    if record.references:
        value["advisories"] = [{"url": item} for item in record.references]
    if record.published_at:
        value["published"] = record.published_at
    if record.updated_at:
        value["updated"] = record.updated_at
    return value


def generate_cyclonedx(result: ScanResult) -> dict[str, Any]:
    dependencies: dict[str, set[str]] = defaultdict(set)
    outgoing: dict[str, list[str]] = defaultdict(list)
    component_ids = {entity.entity_id for entity in result.inventory}
    for relationship in result.relationships:
        if relationship.source_id in component_ids and relationship.target_id in component_ids:
            dependencies[relationship.source_id].add(relationship.target_id)
        outgoing[relationship.source_id].append(f"{relationship.relation}:{relationship.target_id}")

    packages = {package.package_id: package for package in result.packages}
    models = {model.model_id: model for model in result.models}
    components = []
    for entity in result.inventory:
        properties = _version_properties(entity) + [
            {"name": "agentguard:entity:type", "value": entity.entity_type},
            {"name": "agentguard:entity:category", "value": entity.category or "other"},
            {"name": "agentguard:detection:source", "value": entity.detection_source},
            {"name": "agentguard:source:file", "value": entity.file},
            {"name": "agentguard:source:line", "value": str(entity.line)},
        ]
        if entity.framework:
            properties.append({"name": "agentguard:framework:name", "value": entity.framework})
        for relationship in outgoing.get(entity.entity_id, []):
            properties.append({"name": "agentguard:relationship", "value": relationship})
        component: dict[str, Any] = {
            "type": CYCLONEDX_TYPE.get(entity.entity_type, "application"),
            "bom-ref": entity.bom_ref or entity.entity_id,
            "name": entity.name,
            "version": entity.version or "unknown",
            "properties": properties,
        }
        if entity.framework:
            component["group"] = entity.framework
        package = packages.get(entity.entity_id)
        if package:
            if package.purl:
                component["purl"] = package.purl
            if package.licenses:
                component["licenses"] = [{"license": {"name": item}} for item in package.licenses]
            properties.extend([
                {"name": "agentguard:package:ecosystem", "value": package.ecosystem},
                {"name": "agentguard:package:dependency-type", "value": package.dependency_type},
                {"name": "agentguard:package:resolved", "value": str(package.resolved).lower()},
                {"name": "agentguard:package:vulnerability-status", "value": package.vulnerability_status},
            ])
        model = models.get(entity.entity_id)
        if model:
            component["version"] = model.model_revision or "unknown"
            properties.extend([
                {"name": "agentguard:model:provider", "value": model.provider},
                {"name": "agentguard:model:identifier", "value": model.model_identifier},
                {"name": "agentguard:model:revision", "value": model.model_revision or "unknown"},
                {"name": "agentguard:model:access-type", "value": model.access_type},
                {"name": "agentguard:model:framework-package", "value": model.framework_package or "unknown"},
                {"name": "agentguard:model:framework-package-version", "value": model.framework_package_version or "unknown"},
            ])
        components.append(component)

    try:
        serial = uuid.UUID(result.scan.scan_id)
    except ValueError:
        serial = uuid.uuid5(uuid.NAMESPACE_URL, result.scan.scan_id)
    bom: dict[str, Any] = {
        "$schema": "https://cyclonedx.org/schema/bom-1.7.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": result.scan.completed_at or result.scan.started_at,
            "tools": {"components": [{"type": "application", "name": "AgentGuard Core", "version": ENGINE_VERSION}]},
            "properties": [
                {"name": "agentguard:scan:id", "value": result.scan.scan_id},
                {"name": "agentguard:repository", "value": result.scan.root},
                {"name": "agentguard:git:commit", "value": result.scan.git_commit},
                {"name": "agentguard:git:branch", "value": result.scan.git_branch},
            ],
        },
        "components": components,
        "dependencies": [
            {"ref": entity.entity_id, "dependsOn": sorted(dependencies.get(entity.entity_id, set()))}
            for entity in result.inventory
        ],
    }
    if result.vulnerabilities:
        bom["vulnerabilities"] = [
            _cyclonedx_vulnerability(record, packages)
            for record in result.vulnerabilities
        ]
    return bom


def _agent_records(result: ScanResult) -> list[dict[str, Any]]:
    by_id = {entity.entity_id: entity for entity in result.inventory}
    outgoing: dict[str, list[Any]] = defaultdict(list)
    incoming: dict[str, list[Any]] = defaultdict(list)
    for relationship in result.relationships:
        outgoing[relationship.source_id].append(relationship)
        incoming[relationship.target_id].append(relationship)
    agents = []
    for entity in result.inventory:
        if entity.entity_type not in AGENT_TYPES:
            continue
        dependencies = []
        for relationship in outgoing.get(entity.entity_id, []):
            target = by_id.get(relationship.target_id)
            if not target:
                continue
            dependencies.append({
                "relation": relationship.relation,
                "asset_id": target.entity_id,
                "asset_version_id": target.version_id,
                "type": target.entity_type,
                "name": target.name,
                "version": target.version,
                "version_source": target.version_source,
                "framework": target.framework,
                "source": {"file": relationship.evidence_file, "line": relationship.evidence_line},
            })
        parents = []
        for relationship in incoming.get(entity.entity_id, []):
            source = by_id.get(relationship.source_id)
            if source and source.entity_type in AGENT_TYPES:
                parents.append({"relation": relationship.relation, "agent_id": source.entity_id, "name": source.name})
        agents.append({
            "agent_id": entity.entity_id,
            "agent_version_id": entity.version_id,
            "name": entity.name,
            "type": entity.entity_type,
            "qualified_name": entity.qualified_name,
            "version": {
                "value": entity.version,
                "scheme": entity.version_scheme,
                "source": entity.version_source,
                "evidence": entity.version_evidence,
                "content_sha256": entity.content_hash,
            },
            "framework": {
                "name": entity.framework,
                "version": entity.framework_version,
                "package": entity.package_name,
                "package_version": entity.package_version,
            },
            "source": {"file": entity.file, "line": entity.line},
            "capabilities": entity.attributes.get("capabilities", []),
            "attributes": entity.attributes,
            "dependencies": dependencies,
            "parent_agents": parents,
        })
    return agents


def _versions(result: ScanResult) -> list[dict[str, Any]]:
    return [{
        "entity_id": entity.entity_id,
        "version_id": entity.version_id,
        "version": entity.version,
        "scheme": entity.version_scheme,
        "source": entity.version_source,
        "content_sha256": entity.content_hash,
        "source_location": {"file": entity.file, "line": entity.line},
    } for entity in result.inventory]


def generate_agent_bom_v2(result: ScanResult) -> dict[str, Any]:
    """Compatibility exporter for consumers pinned to Agent BOM 2.0."""

    agents = _agent_records(result)
    type_counts = Counter(entity.entity_type for entity in result.inventory)
    return {
        "schema": "agentguard-agent-bom/2.0",
        "scan": {
            "scan_id": result.scan.scan_id,
            "repository": result.scan.root,
            "remote": result.scan.git_remote,
            "commit": result.scan.git_commit,
            "branch": result.scan.git_branch,
        },
        "summary": {
            "agents": len(agents),
            "assets": len(result.inventory),
            "relationships": len(result.relationships),
            "asset_types": dict(type_counts),
        },
        "agents": agents,
        "assets": [entity.to_dict() for entity in result.inventory],
        "versions": _versions(result),
        "relationships": [relationship.to_dict() for relationship in result.relationships],
    }


def generate_agent_bom(result: ScanResult) -> dict[str, Any]:
    """AgentGuard's rich internal Agent BOM 3.0 representation."""

    agents = _agent_records(result)
    type_counts = Counter(entity.entity_type for entity in result.inventory)

    def assets_of(types: set[str]) -> list[dict[str, Any]]:
        return [entity.to_dict() for entity in result.inventory if entity.entity_type in types]

    return {
        "schema": "agentguard-agent-bom/3.0",
        "scan": {
            "scan_id": result.scan.scan_id,
            "repository": result.scan.root,
            "remote": result.scan.git_remote,
            "commit": result.scan.git_commit,
            "branch": result.scan.git_branch,
        },
        "summary": {
            "agents": len(agents),
            "models": len(result.models),
            "tools": sum(entity.entity_type in TOOL_TYPES for entity in result.inventory),
            "skills": sum(entity.entity_type in SKILL_TYPES for entity in result.inventory),
            "mcp_components": sum(entity.entity_type in MCP_TYPES for entity in result.inventory),
            "data_retrieval_assets": sum(entity.entity_type in DATA_TYPES for entity in result.inventory),
            "memory_assets": sum(entity.entity_type in MEMORY_TYPES for entity in result.inventory),
            "packages": len(result.packages),
            "vulnerabilities": len(result.vulnerabilities),
            "static_findings": len(result.findings),
            "assets": len(result.inventory),
            "relationships": len(result.relationships),
            "asset_types": dict(type_counts),
        },
        "agents": agents,
        "models": [model.to_dict() for model in result.models],
        "tools": assets_of(TOOL_TYPES),
        "skills": assets_of(SKILL_TYPES),
        "mcp_components": assets_of(MCP_TYPES),
        "data_retrieval_assets": assets_of(DATA_TYPES),
        "memory": assets_of(MEMORY_TYPES),
        "packages": [package.to_dict() for package in result.packages],
        "vulnerabilities": [vulnerability.to_dict() for vulnerability in result.vulnerabilities],
        "static_findings": [finding.to_dict() for finding in result.findings],
        "relationships": [relationship.to_dict() for relationship in result.relationships],
        "versions": _versions(result),
        "assets": [entity.to_dict() for entity in result.inventory],
    }
