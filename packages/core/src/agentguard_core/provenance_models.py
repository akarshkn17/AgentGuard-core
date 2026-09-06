from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class RelationshipNature(str, Enum):
    """How strongly a graph relationship is supported by scanner evidence."""

    EXPLICIT_DIRECT = "explicit/direct"
    INFERRED = "inferred"
    TRANSITIVE_DERIVED = "transitive/derived"


@dataclass(frozen=True, slots=True)
class GraphEvidence:
    file: str = ""
    line: int = 1
    column: int = 0
    symbol: str = ""
    detail: str = ""
    edge_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            key: value
            for key, value in asdict(self).items()
            if value not in ("", None) and not (key == "column" and value == 0)
        }


@dataclass(slots=True)
class KnowledgeGraphNode:
    node_id: str
    kind: str
    node_class: str
    subtype: str
    label: str
    source: dict[str, Any] = field(default_factory=dict)
    risk: dict[str, Any] = field(default_factory=dict)
    attributes: dict[str, Any] = field(default_factory=dict)
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id,
            "kind": self.kind,
            "node_class": self.node_class,
            "subtype": self.subtype,
            "label": self.label,
            **self.data,
            "source": self.source,
            "risk": self.risk,
            "attributes": self.attributes,
        }


@dataclass(slots=True)
class KnowledgeGraphEdge:
    edge_id: str
    source: str
    target: str
    relation: str
    relationship_type: RelationshipNature
    confidence: str
    derivation_method: str
    evidence: list[dict[str, Any]]
    finding_ids: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        # `evidence` is retained for graph 1.0 clients. `source_evidence` makes
        # the derivation contract explicit for Milestone 2 consumers.
        return {
            "id": self.edge_id,
            "source": self.source,
            "target": self.target,
            "relation": self.relation,
            "directed": True,
            "relationship_type": self.relationship_type.value,
            "confidence": self.confidence,
            "derivation_method": self.derivation_method,
            "source_evidence": list(self.evidence),
            "evidence": list(self.evidence),
            "finding_ids": list(self.finding_ids),
            "attributes": self.attributes,
        }


@dataclass(slots=True)
class AssetAttribution:
    directly_affected_assets: list[str] = field(default_factory=list)
    transitively_affected_assets: list[str] = field(default_factory=list)
    source_symbol_ids: list[str] = field(default_factory=list)
    sink_symbol_ids: list[str] = field(default_factory=list)
    ownership_paths: dict[str, list[str]] = field(default_factory=dict)
    confidence: str = "unresolved"
    derivation_method: str = "repository-fallback"
    evidence: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
