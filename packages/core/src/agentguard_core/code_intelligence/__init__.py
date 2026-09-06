"""Reusable, bounded code-intelligence primitives for one AgentGuard scan."""

from .dataflow import AbstractStore, TaintValue
from .index import ProjectFunction, ProjectIndex, ProjectModule
from .models import (
    AbstractLocation,
    AbstractLocationKind,
    AbstractValue,
    AnalysisLimits,
    CallEdge,
    CallSite,
    CodeSymbol,
    DataFlowEdge,
    ResolutionConfidence,
    SanitizerResult,
    SanitizerState,
    SourceLocation,
    SourceRange,
    SymbolKind,
)
from .resolver import CallResolution, CallResolver
from .sanitizers import SanitizerRegistry
from .session import CodeIntelligenceSession

__all__ = [
    "AbstractLocation",
    "AbstractLocationKind",
    "AbstractStore",
    "AbstractValue",
    "AnalysisLimits",
    "CallEdge",
    "CallResolution",
    "CallResolver",
    "CallSite",
    "CodeIntelligenceSession",
    "CodeSymbol",
    "DataFlowEdge",
    "ProjectFunction",
    "ProjectIndex",
    "ProjectModule",
    "ResolutionConfidence",
    "SanitizerRegistry",
    "SanitizerResult",
    "SanitizerState",
    "SourceLocation",
    "SourceRange",
    "SymbolKind",
    "TaintValue",
]
