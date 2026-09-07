from __future__ import annotations

import hashlib
from pathlib import Path

from .index import ProjectIndex
from .models import AnalysisLimits, CallEdge, CallSite, DataFlowEdge, node_range
from .resolver import CallResolver


class CodeIntelligenceSession:
    """One persistent-in-memory code intelligence state per repository scan."""

    def __init__(self, root: Path, sources: dict[Path, str], limits: AnalysisLimits | None = None):
        self.root = root.resolve()
        self.sources = {path.resolve(): source for path, source in sources.items()}
        self.limits = limits or AnalysisLimits()
        self.index = ProjectIndex(self.root, self.sources)
        self.resolver = CallResolver(self.index)
        self.index.set_resolver(self.resolver)
        self.call_sites: list[CallSite] = []
        self.call_edges: list[CallEdge] = []
        self.data_flow_edges: list[DataFlowEdge] = []
        self._data_flow_edge_set: set[DataFlowEdge] = set()
        self._contexts: dict[str, set[tuple[str, ...]]] = {}
        self._build_call_graph()

    @classmethod
    def from_files(cls, root: Path, paths: list[Path], limits: AnalysisLimits | None = None) -> CodeIntelligenceSession:
        sources = {path.resolve(): path.read_text(encoding="utf-8", errors="ignore") for path in paths}
        return cls(root, sources, limits)

    def _build_call_graph(self) -> None:
        for function in self.index.functions.values():
            caller_id = function.symbol.symbol_id if function.symbol else function.qualname
            for call in self.index.iter_function_calls(function):
                expression = self.index.canonical(call.func, function)
                location = node_range(str(function.module.path), call)
                material = f"{caller_id}|{expression}|{location.start.line}|{location.start.column}"
                call_id = f"CALL-{hashlib.sha256(material.encode()).hexdigest()[:20].upper()}"
                site = CallSite(
                    call_id,
                    caller_id,
                    expression,
                    location,
                    len(call.args),
                    tuple(keyword.arg or "**" for keyword in call.keywords),
                )
                self.call_sites.append(site)
                resolution = self.resolver.resolve(call, function)
                if resolution.target and resolution.target.symbol:
                    self.call_edges.append(
                        CallEdge(
                            call_id,
                            caller_id,
                            resolution.target.symbol.symbol_id,
                            resolution.confidence,
                            resolution.method,
                        )
                    )

    def allow_context(self, symbol: str, context: tuple[str, ...]) -> bool:
        if len(context) > self.limits.max_call_depth:
            return False
        contexts = self._contexts.setdefault(symbol, set())
        if context in contexts:
            return True
        if len(contexts) >= self.limits.max_contexts_per_symbol:
            return False
        contexts.add(context)
        return True

    def record_data_flow(self, edge: DataFlowEdge) -> None:
        if edge in self._data_flow_edge_set:
            return
        self._data_flow_edge_set.add(edge)
        self.data_flow_edges.append(edge)
