from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class ModelEntity:
    """Normalized model identity without treating a model name as a revision."""

    model_id: str
    logical_identity: str
    provider: str
    model_identifier: str
    model_revision: str = ""
    deployment_name: str = ""
    endpoint_service: str = ""
    access_type: str = "remote_api"
    framework: str = ""
    framework_package: str = ""
    framework_package_version: str = ""
    configuration_source: str = ""
    source_file: str = ""
    source_line: int = 1
    parameters: dict[str, Any] = field(default_factory=dict)
    repository: str = ""
    repository_revision: str = ""
    content_revision: str = ""
    entity_version_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class PackageEntity:
    """One observed package version or unresolved manifest constraint."""

    package_id: str
    name: str
    normalized_name: str
    ecosystem: str
    version: str
    purl: str = ""
    dependency_type: str = "transitive"
    manifest_origins: list[str] = field(default_factory=list)
    lockfile_origins: list[str] = field(default_factory=list)
    dependency_path: list[str] = field(default_factory=list)
    licenses: list[str] = field(default_factory=list)
    source_evidence: list[dict[str, Any]] = field(default_factory=list)
    requested_version: str = ""
    resolved: bool = False
    dependencies: list[str] = field(default_factory=list)
    vulnerability_status: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class VulnerabilityRecord:
    """Provider-neutral vulnerability record for one affected package."""

    vulnerability_id: str
    canonical_id: str
    aliases: list[str]
    source: str
    severity: str
    affected_package_id: str
    affected_version_status: str
    reachability: str = "unknown"
    exploitability: str = "unknown"
    package_presence: str = "present"
    cvss: list[dict[str, Any]] = field(default_factory=list)
    cwe: list[str] = field(default_factory=list)
    affected_ranges: list[dict[str, Any]] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    published_at: str = ""
    updated_at: str = ""
    enrichment_timestamp: str = ""
    summary: str = ""
    details: str = ""
    affected_version: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> VulnerabilityRecord:
        fields = cls.__dataclass_fields__
        return cls(**{key: item for key, item in value.items() if key in fields})
