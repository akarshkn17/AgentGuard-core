from __future__ import annotations

from collections import defaultdict

from .bom_models import ModelEntity, PackageEntity
from .contracts import ScanResult
from .models import InventoryEntity, Relationship
from .package_inventory import normalize_package_name

AGENT_TYPES = {"agent", "sub_agent", "orchestrator", "agent_proxy"}
TOOL_TYPES = {"tool", "function_tool", "mcp_tool"}


def _provider(entity: InventoryEntity) -> str:
    explicit = str(entity.attributes.get("provider", "")).strip().lower()
    if explicit:
        return explicit
    material = " ".join(
        str(value)
        for value in (
            entity.framework,
            entity.attributes.get("constructor", ""),
            entity.attributes.get("model_id", ""),
            entity.attributes.get("model", ""),
        )
    ).lower()
    if "azure" in material:
        return "azure-openai"
    if "anthropic" in material or "claude" in material:
        return "anthropic"
    if "bedrock" in material:
        return "aws-bedrock"
    if any(value in material for value in ("vertex", "gemini", "google", "generative")):
        return "google"
    if any(value in material for value in ("huggingface", "transformers", "from_pretrained")):
        return "huggingface"
    if "openai" in material or str(entity.name).lower().startswith(("gpt-", "o1", "o3", "o4")):
        return "openai"
    return "unknown"


def _access_type(provider: str, entity: InventoryEntity) -> str:
    explicit = str(entity.attributes.get("access_type", ""))
    if explicit:
        return explicit
    if provider == "huggingface":
        return "downloaded"
    if provider in {"azure-openai", "aws-bedrock", "google"}:
        return "managed_service"
    if entity.attributes.get("local_path"):
        return "local"
    return "remote_api"


def _model_identifier(entity: InventoryEntity) -> str:
    for key in ("model_identifier", "model_id", "model", "model_name", "modelId", "repository"):
        value = entity.attributes.get(key)
        if isinstance(value, str) and value:
            return value
    return entity.name


def build_model_inventory(result: ScanResult) -> tuple[list[ModelEntity], list[Relationship]]:
    """Normalize discovered model assets and add v3 relationship vocabulary."""

    entities = {entity.entity_id: entity for entity in result.inventory}
    packages_by_name: dict[str, list[PackageEntity]] = defaultdict(list)
    for package in result.packages:
        packages_by_name[normalize_package_name(package.name, package.ecosystem)].append(package)

    extra_relationships: list[Relationship] = []
    existing = {(item.source_id, item.relation, item.target_id) for item in result.relationships}

    def add_relationship(source_id: str, relation: str, target_id: str, original: Relationship, method: str) -> None:
        key = (source_id, relation, target_id)
        if key in existing:
            return
        existing.add(key)
        extra_relationships.append(Relationship(
            source_id,
            relation,
            target_id,
            original.evidence_file,
            original.evidence_line,
            {**original.attributes, "v3_semantic_relation": True},
            original.relationship_type,
            original.confidence,
            method,
            list(original.source_evidence),
        ))

    model_endpoints: dict[str, str] = {}
    for relationship in result.relationships:
        source = entities.get(relationship.source_id)
        target = entities.get(relationship.target_id)
        if target and target.entity_type == "model" and source:
            if source.entity_type in AGENT_TYPES:
                add_relationship(source.entity_id, "AGENT_USES_MODEL", target.entity_id, relationship, "normalized-agent-model-relationship")
            elif source.entity_type in TOOL_TYPES:
                add_relationship(source.entity_id, "TOOL_USES_MODEL", target.entity_id, relationship, "normalized-tool-model-relationship")
        if source and source.entity_type == "model" and target and target.entity_type in {"llm_endpoint", "model_endpoint", "service", "provider"}:
            model_endpoints[source.entity_id] = target.name
            add_relationship(source.entity_id, "MODEL_ACCESSED_VIA", target.entity_id, relationship, "normalized-model-endpoint-relationship")

    models: list[ModelEntity] = []
    for entity in result.inventory:
        if entity.entity_type not in {"model", "embedding", "embedding_model"}:
            continue
        provider = _provider(entity)
        identifier = _model_identifier(entity)
        parameters = entity.attributes.get("parameters")
        parameters = dict(parameters) if isinstance(parameters, dict) else {}
        revision = str(entity.attributes.get("revision") or entity.attributes.get("model_revision") or "")
        repository = str(entity.attributes.get("repository") or (identifier if provider == "huggingface" else ""))
        framework_package = entity.package_name
        framework_package_version = entity.package_version
        framework_candidates = packages_by_name.get(normalize_package_name(framework_package, "PyPI"), []) if framework_package else []
        if framework_candidates:
            resolved_framework = min(framework_candidates, key=lambda item: (item.dependency_type != "direct", item.version))
            framework_package = resolved_framework.name
            framework_package_version = resolved_framework.version
        models.append(ModelEntity(
            entity.entity_id,
            entity.qualified_name or identifier,
            provider,
            identifier,
            revision,
            str(entity.attributes.get("deployment_name") or entity.attributes.get("azure_deployment") or ""),
            model_endpoints.get(entity.entity_id) or str(entity.attributes.get("endpoint") or entity.attributes.get("base_url") or entity.attributes.get("azure_endpoint") or ""),
            _access_type(provider, entity),
            entity.framework,
            framework_package,
            framework_package_version,
            str(entity.attributes.get("configuration_source") or entity.detection_source),
            entity.file,
            entity.line,
            parameters,
            repository,
            revision,
            str(entity.attributes.get("content_revision") or entity.attributes.get("content_hash") or ""),
            entity.version_id,
        ))
        package_names = [entity.package_name]
        constructor = str(entity.attributes.get("constructor", "")).lower()
        if provider == "huggingface" or "transformers" in constructor:
            package_names.append("transformers")
        for package_name in package_names:
            if not package_name:
                continue
            normalized = normalize_package_name(package_name, "PyPI")
            candidates = packages_by_name.get(normalized, [])
            if not candidates:
                continue
            package = min(candidates, key=lambda item: (item.dependency_type != "direct", item.version))
            synthetic = Relationship(
                entity.entity_id,
                "MODEL_IMPLEMENTED_WITH_PACKAGE",
                package.package_id,
                entity.file,
                entity.line,
                {"framework_package": package.name},
                "explicit/direct",
                "high",
                "framework-package-mapping",
                [{"file": entity.file, "line": entity.line, "detail": f"{entity.framework or provider} model wrapper"}],
            )
            add_relationship(entity.entity_id, synthetic.relation, package.package_id, synthetic, synthetic.derivation_method)

    return models, extra_relationships
