from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SymbolKind(str, Enum):
    MODULE = "module"
    CLASS = "class"
    FUNCTION = "function"
    METHOD = "method"
    NESTED_FUNCTION = "nested_function"
    PARAMETER = "parameter"


class AbstractLocationKind(str, Enum):
    LOCAL = "local"
    PARAMETER = "parameter"
    RETURN = "return"
    ATTRIBUTE = "attribute"
    CONTAINER = "container"


class ResolutionConfidence(str, Enum):
    EXACT = "exact"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNRESOLVED = "unresolved"


class SanitizerState(str, Enum):
    PROVEN = "proven"
    PARTIAL = "partial"
    UNVERIFIED = "unverified"
    ABSENT = "absent"


@dataclass(frozen=True, slots=True)
class SourceLocation:
    file: str
    line: int
    column: int = 0
    offset: int | None = None


@dataclass(frozen=True, slots=True)
class SourceRange:
    start: SourceLocation
    end: SourceLocation


@dataclass(slots=True)
class CodeSymbol:
    symbol_id: str
    kind: SymbolKind
    name: str
    qualified_name: str
    module: str
    source_range: SourceRange
    parent_symbol_id: str = ""
    decorators: tuple[str, ...] = ()
    parameters: tuple[str, ...] = ()
    is_async: bool = False
    ast_node: ast.AST | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class AbstractLocation:
    kind: AbstractLocationKind
    owner_symbol_id: str
    root: str
    path: tuple[str, ...] = ()

    def child(self, segment: str, kind: AbstractLocationKind | None = None) -> "AbstractLocation":
        return AbstractLocation(kind or self.kind, self.owner_symbol_id, self.root, (*self.path, segment))


@dataclass(slots=True)
class AbstractValue:
    known_literals: set[str | int | float | bool | None] = field(default_factory=set)
    type_names: set[str] = field(default_factory=set)
    aliases: set[AbstractLocation] = field(default_factory=set)


@dataclass(frozen=True, slots=True)
class SanitizerResult:
    state: SanitizerState
    contract_id: str = ""
    protected_labels: frozenset[str] = frozenset()
    applicable_sinks: frozenset[str] = frozenset()
    reason: str = ""
    evidence: SourceRange | None = None


@dataclass(frozen=True, slots=True)
class CallSite:
    call_site_id: str
    caller_symbol_id: str
    callee_expression: str
    source_range: SourceRange
    argument_count: int = 0
    keyword_names: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CallEdge:
    call_site_id: str
    caller_symbol_id: str
    callee_symbol_id: str
    confidence: ResolutionConfidence
    resolution_method: str


@dataclass(frozen=True, slots=True)
class DataFlowEdge:
    source: AbstractLocation | None
    target: AbstractLocation
    operation: str
    source_range: SourceRange
    context: tuple[str, ...] = ()
    confidence: ResolutionConfidence = ResolutionConfidence.EXACT


@dataclass(frozen=True, slots=True)
class AnalysisLimits:
    max_call_depth: int = 12
    max_contexts_per_symbol: int = 16
    max_alias_depth: int = 8
    max_container_depth: int = 4
    max_loop_iterations: int = 2
    max_evidence_nodes: int = 64

    def __post_init__(self) -> None:
        for name, value in self.__dict__.items() if hasattr(self, "__dict__") else (
            (slot, getattr(self, slot)) for slot in self.__slots__
        ):
            if not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


def node_range(path: str, node: ast.AST) -> SourceRange:
    start = SourceLocation(path, getattr(node, "lineno", 1), getattr(node, "col_offset", 0))
    end = SourceLocation(
        path,
        getattr(node, "end_lineno", start.line),
        getattr(node, "end_col_offset", start.column),
    )
    return SourceRange(start, end)


def metadata_dict(**values: Any) -> dict[str, Any]:
    """Small helper used by future graph adapters without coupling models to JSON."""
    return {key: value for key, value in values.items() if value not in (None, "", (), [], {})}
