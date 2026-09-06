from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class EvidenceNode:
    """One deterministic step in an evidence or taint path."""

    kind: str
    label: str
    file: str
    line: int = 1
    symbol: str = ""
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Finding:
    """Canonical scanner finding.

    The leading fields intentionally preserve AgentGuard 0.2's Finding constructor
    so the existing analyzers can be reused without changing detection logic.
    Enrichment fields are attached after detection by FindingEnricher.
    """

    rule_id: str
    name: str
    severity: str
    file: str
    line: int
    message: str
    evidence: list[EvidenceNode] = field(default_factory=list)
    code: str = ""
    analysis_type: str = "taint"
    llm_verdict: str | None = None
    llm_reason: str | None = None
    fingerprint: str = ""
    semantic_anchor: str = ""
    engine_metadata: dict[str, Any] = field(default_factory=dict)

    # v0.3 canonical/enrichment fields. These do not participate in detection.
    finding_id: str = ""
    title: str = ""
    description: str = ""
    category: str = ""
    remediation: list[str] = field(default_factory=list)
    source_description: str = ""
    sink_description: str = ""
    detection_logic: str = ""
    references: list[str] = field(default_factory=list)
    mappings: dict[str, list[str]] = field(default_factory=dict)
    cwe: list[str] = field(default_factory=list)
    rule_version: str = "1"
    confidence: str = "deterministic"
    schema_version: str = "1.1"
    directly_affected_assets: list[str] = field(default_factory=list)
    transitively_affected_assets: list[str] = field(default_factory=list)
    attribution: dict[str, Any] = field(default_factory=dict)

    def finalize(self, repository_root: Path | None = None) -> Finding:
        """Create a stable, line-number-independent semantic fingerprint."""

        normalized_code = re.sub(r"\s+", " ", self.code.strip())
        if self.semantic_anchor:
            anchor = self.semantic_anchor
        else:
            path = Path(self.file)
            if repository_root:
                try:
                    path = path.resolve().relative_to(repository_root.resolve())
                except (OSError, ValueError):
                    pass
            endpoint = self.evidence[-1] if self.evidence else None
            symbol = endpoint.symbol if endpoint else ""
            anchor = f"{path.as_posix().lower()}|{symbol}|{normalized_code}"
        payload = f"{self.rule_id}|{self.analysis_type}|{anchor}"
        self.fingerprint = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]
        self.finding_id = f"AGF-{self.fingerprint.upper()}"
        if not self.title:
            self.title = self.name
        return self

    def normalize_paths(self, repository_root: Path) -> None:
        """Convert machine-absolute evidence paths into repository-relative paths."""
        root = repository_root.resolve()

        def rel(value: str) -> str:
            try:
                return Path(value).resolve().relative_to(root).as_posix()
            except (OSError, ValueError):
                return Path(value).as_posix()

        self.file = rel(self.file)
        for node in self.evidence:
            node.file = rel(node.file)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        # A normalized location object makes the JSON contract friendlier to SDK/API clients
        # while retaining old flat file/line fields for compatibility.
        data["location"] = {"file": self.file, "line": self.line}
        return data


@dataclass(slots=True)
class InventoryEntity:
    entity_id: str
    entity_type: str
    name: str
    file: str
    line: int
    framework: str = ""
    framework_version: str = ""
    content_hash: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)
    qualified_name: str = ""

    # AgentGuard v0.3 inventory/BOM normalization fields.
    category: str = ""
    version: str = ""
    version_source: str = ""
    package_name: str = ""
    package_version: str = ""
    detection_source: str = "code_analysis"
    bom_ref: str = ""
    version_id: str = ""
    version_scheme: str = ""
    version_evidence: dict[str, Any] = field(default_factory=dict)

    def finalize(self, repository_root: Path | None = None) -> InventoryEntity:
        if repository_root:
            try:
                self.file = Path(self.file).resolve().relative_to(repository_root.resolve()).as_posix()
            except (OSError, ValueError):
                self.file = Path(self.file).as_posix()
        if not self.version:
            if self.framework_version:
                self.version = self.framework_version
                self.version_source = self.version_source or "dependency_manifest"
            elif self.content_hash:
                self.version = f"sha256:{self.content_hash[:16]}"
                self.version_source = self.version_source or "content_hash"
            else:
                self.version = "unknown"
                self.version_source = self.version_source or "unknown"
        if not self.version_scheme:
            if self.version_source in {"agent_manifest", "project_manifest", "constructor", "declared"}:
                self.version_scheme = "declared"
            elif self.version_source == "git_tag":
                self.version_scheme = "git-tag"
            elif self.version_source == "git_commit":
                self.version_scheme = "git-commit"
            elif self.version_source == "content_hash":
                self.version_scheme = "content-digest"
            elif self.version_source == "model_identifier":
                self.version_scheme = "model-id"
            else:
                self.version_scheme = "unknown"
        self.bom_ref = self.bom_ref or self.entity_id
        if not self.version_id:
            material = f"{self.entity_id}|{self.version}|{self.content_hash}"
            self.version_id = f"AGV-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:20].upper()}"
        if not self.version_evidence:
            self.version_evidence = {"source": self.version_source, "value": self.version}
        return self

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Relationship:
    source_id: str
    relation: str
    target_id: str
    evidence_file: str = ""
    evidence_line: int = 1
    attributes: dict[str, Any] = field(default_factory=dict)
    relationship_type: str = "explicit/direct"
    confidence: str = "exact"
    derivation_method: str = "resolved-static-reference"
    source_evidence: list[dict[str, Any]] = field(default_factory=list)

    def normalize_paths(self, repository_root: Path) -> None:
        if self.evidence_file:
            try:
                self.evidence_file = Path(self.evidence_file).resolve().relative_to(repository_root.resolve()).as_posix()
            except (OSError, ValueError):
                self.evidence_file = Path(self.evidence_file).as_posix()
        if not self.source_evidence and self.evidence_file:
            self.source_evidence = [{"file": self.evidence_file, "line": self.evidence_line}]
        for evidence in self.source_evidence:
            value = evidence.get("file")
            if not value:
                continue
            try:
                evidence["file"] = Path(value).resolve().relative_to(repository_root.resolve()).as_posix()
            except (OSError, ValueError):
                evidence["file"] = Path(value).as_posix()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
