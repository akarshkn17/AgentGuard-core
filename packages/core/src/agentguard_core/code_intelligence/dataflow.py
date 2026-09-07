from __future__ import annotations

from dataclasses import dataclass, field

from ..models import EvidenceNode
from .models import (
    AbstractLocation,
    AbstractLocationKind,
    AbstractValue,
    DataFlowEdge,
    SanitizerResult,
    SanitizerState,
)


@dataclass(slots=True)
class TaintValue:
    labels: set[str] = field(default_factory=set)
    path: list[EvidenceNode] = field(default_factory=list)
    sanitizers: list[SanitizerResult] = field(default_factory=list)
    abstract: AbstractValue = field(default_factory=AbstractValue)

    def merge(self, other: TaintValue) -> TaintValue:
        if not self.labels and not self.abstract.aliases and not self.abstract.known_literals:
            return other.copy()
        if not other.labels and not other.abstract.aliases and not other.abstract.known_literals:
            return self.copy()
        path = self.path if len(self.path) >= len(other.path) else other.path
        sanitizers = list(dict.fromkeys([*self.sanitizers, *other.sanitizers]))
        return TaintValue(
            set(self.labels) | set(other.labels),
            list(path),
            sanitizers,
            AbstractValue(
                set(self.abstract.known_literals) | set(other.abstract.known_literals),
                set(self.abstract.type_names) | set(other.abstract.type_names),
                set(self.abstract.aliases) | set(other.abstract.aliases),
            ),
        )

    def copy(self) -> TaintValue:
        return TaintValue(
            set(self.labels),
            list(self.path),
            list(self.sanitizers),
            AbstractValue(
                set(self.abstract.known_literals),
                set(self.abstract.type_names),
                set(self.abstract.aliases),
            ),
        )

    def through(self, node: EvidenceNode, *, max_nodes: int = 64) -> TaintValue:
        value = self.copy()
        if value.labels:
            value.path = [*value.path, node][-max_nodes:]
        return value

    def sanitized(self, result: SanitizerResult, node: EvidenceNode | None = None) -> TaintValue:
        value = self.copy()
        value.sanitizers.append(result)
        if node is not None and value.labels:
            value.path.append(node)
        return value

    def effective_labels(self, sinks: set[str]) -> set[str]:
        labels = set(self.labels)
        for sanitizer in self.sanitizers:
            if sanitizer.state is not SanitizerState.PROVEN:
                continue
            if sanitizer.applicable_sinks and not sinks.intersection(sanitizer.applicable_sinks):
                continue
            labels.difference_update(sanitizer.protected_labels)
        return labels


class AbstractStore:
    """Bounded abstract memory for locals, attributes and container entries."""

    def __init__(self, *, max_alias_depth: int = 8, max_container_depth: int = 4):
        self.values: dict[AbstractLocation, TaintValue] = {}
        self.aliases: dict[AbstractLocation, AbstractLocation] = {}
        self.edges: list[DataFlowEdge] = []
        self._edge_set: set[DataFlowEdge] = set()
        self.max_alias_depth = max_alias_depth
        self.max_container_depth = max_container_depth

    def fork(self) -> AbstractStore:
        child = AbstractStore(
            max_alias_depth=self.max_alias_depth,
            max_container_depth=self.max_container_depth,
        )
        child.values = {key: value.copy() for key, value in self.values.items()}
        child.aliases = dict(self.aliases)
        return child

    def record_edge(self, edge: DataFlowEdge) -> None:
        if edge in self._edge_set:
            return
        self._edge_set.add(edge)
        self.edges.append(edge)

    def _bounded_path(self, *parts: tuple[str, ...]) -> tuple[str, ...]:
        """Join abstract container paths without creating an unbounded tuple.

        Alias chains may prepend a path at every hop.  Bound each join while it
        is being constructed so a cyclic or long alias chain cannot allocate an
        exponentially growing intermediate tuple before ``write`` gets a chance
        to apply the container-depth limit.
        """
        combined: list[str] = []
        for part in parts:
            for segment in part:
                if segment == "*":
                    if len(combined) >= self.max_container_depth:
                        combined = combined[: self.max_container_depth - 1]
                    combined.append("*")
                    return tuple(combined)
                if len(combined) >= self.max_container_depth:
                    return (*combined[: self.max_container_depth - 1], "*")
                combined.append(segment)
        return tuple(combined)

    def resolve(self, location: AbstractLocation) -> AbstractLocation:
        current = AbstractLocation(
            location.kind,
            location.owner_symbol_id,
            location.root,
            self._bounded_path(location.path),
        )
        visited: set[AbstractLocation] = set()
        for _ in range(self.max_alias_depth):
            base = AbstractLocation(current.kind, current.owner_symbol_id, current.root)
            if base in visited:
                break
            visited.add(base)
            target = self.aliases.get(base)
            if target is None:
                break
            path = self._bounded_path(target.path, current.path)
            current = AbstractLocation(target.kind, target.owner_symbol_id, target.root, path)
        return current

    def bind_alias(self, source: AbstractLocation, target: AbstractLocation) -> None:
        source_base = AbstractLocation(source.kind, source.owner_symbol_id, source.root)
        self.aliases[source_base] = self.resolve(target)

    def read(self, location: AbstractLocation) -> TaintValue:
        resolved = self.resolve(location)
        exact = self.values.get(resolved)
        if exact is not None:
            return exact.copy()
        if resolved.path:
            wildcard = AbstractLocation(resolved.kind, resolved.owner_symbol_id, resolved.root, (*resolved.path[:-1], "*"))
            if wildcard in self.values:
                return self.values[wildcard].copy()
        return TaintValue(abstract=AbstractValue(aliases={resolved}))

    def contains(self, location: AbstractLocation) -> bool:
        resolved = self.resolve(location)
        if resolved in self.values:
            return True
        if resolved.path:
            wildcard = AbstractLocation(resolved.kind, resolved.owner_symbol_id, resolved.root, (*resolved.path[:-1], "*"))
            return wildcard in self.values
        return False

    def write(self, location: AbstractLocation, value: TaintValue) -> AbstractLocation:
        resolved = self.resolve(location)
        stored = value.copy()
        stored.abstract.aliases.add(resolved)
        self.values[resolved] = stored
        return resolved

    def merge_from(self, other: AbstractStore) -> None:
        for location, value in other.values.items():
            self.values[location] = self.values.get(location, TaintValue()).merge(value)
        for source, target in other.aliases.items():
            if source not in self.aliases or self.aliases[source] == target:
                self.aliases[source] = target
        for edge in other.edges:
            self.record_edge(edge)

    @staticmethod
    def local(owner: str, name: str, *, parameter: bool = False) -> AbstractLocation:
        return AbstractLocation(
            AbstractLocationKind.PARAMETER if parameter else AbstractLocationKind.LOCAL,
            owner,
            name,
        )
