from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .bom_models import ModelEntity, PackageEntity, VulnerabilityRecord
from .models import Finding, InventoryEntity, Relationship

if TYPE_CHECKING:
    from .code_intelligence import CodeIntelligenceSession
    from .vulnerabilities import VulnerabilityProvider

CONTRACT_VERSION = "1.2"
ENGINE_ID = "agentguard-core"
ENGINE_VERSION = "0.4.0"

@dataclass(slots=True)
class ScanRequest:
    root: Path
    rules_dir: Path | None = None
    include_inventory: bool = True
    enable_tree_sitter: bool = True
    rule_ids: set[str] = field(default_factory=set)
    include_skill_analysis: bool = True
    allow_network_enrichment: bool = False
    vulnerability_cache_path: Path | None = None
    vulnerability_cache_ttl_seconds: int = 86_400
    vulnerability_provider: VulnerabilityProvider | None = None

@dataclass(slots=True)
class ScanMetadata:
    scan_id: str
    root: str
    started_at: str
    completed_at: str = ""
    status: str = "running"
    git_commit: str = ""
    git_branch: str = ""
    git_remote: str = ""

@dataclass(slots=True)
class EngineInfo:
    engine_id: str = ENGINE_ID
    version: str = ENGINE_VERSION
    kind: str = "static-analysis"

@dataclass(slots=True)
class ScanMetrics:
    files_scanned: int = 0
    findings: int = 0
    inventory_entities: int = 0
    relationships: int = 0
    models: int = 0
    packages: int = 0
    vulnerabilities: int = 0
    duration_ms: int = 0

@dataclass(slots=True)
class ScanError:
    stage: str
    path: str
    message: str

@dataclass(slots=True)
class ScanResult:
    scan: ScanMetadata
    findings: list[Finding] = field(default_factory=list)
    inventory: list[InventoryEntity] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)
    models: list[ModelEntity] = field(default_factory=list)
    packages: list[PackageEntity] = field(default_factory=list)
    vulnerabilities: list[VulnerabilityRecord] = field(default_factory=list)
    errors: list[ScanError] = field(default_factory=list)
    metrics: ScanMetrics = field(default_factory=ScanMetrics)
    engines: list[EngineInfo] = field(default_factory=lambda: [EngineInfo()])
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    contract_version: str = CONTRACT_VERSION
    # In-memory analysis state used by evidence-backed graph exporters. It is
    # deliberately excluded from the serialized ScanResult 1.2 contract.
    code_intelligence: CodeIntelligenceSession | None = field(default=None, repr=False, compare=False)

    def finish(self, *, status: str = "completed") -> ScanResult:
        self.scan.status = status
        self.scan.completed_at = datetime.now(timezone.utc).isoformat()
        self.metrics.findings = len(self.findings)
        self.metrics.inventory_entities = len(self.inventory)
        self.metrics.relationships = len(self.relationships)
        self.metrics.models = len(self.models)
        self.metrics.packages = len(self.packages)
        self.metrics.vulnerabilities = len(self.vulnerabilities)
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "scan": asdict(self.scan),
            "engines": [asdict(item) for item in self.engines],
            "findings": [item.to_dict() for item in self.findings],
            "inventory": [item.to_dict() for item in self.inventory],
            "relationships": [item.to_dict() for item in self.relationships],
            "models": [item.to_dict() for item in self.models],
            "packages": [item.to_dict() for item in self.packages],
            "vulnerabilities": [item.to_dict() for item in self.vulnerabilities],
            "artifacts": self.artifacts,
            "metrics": asdict(self.metrics),
            "errors": [asdict(item) for item in self.errors],
        }
