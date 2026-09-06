from __future__ import annotations

import hashlib
from collections import Counter, defaultdict, deque
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .code_intelligence import CodeSymbol, ResolutionConfidence, SymbolKind
from .contracts import ScanResult
from .frameworks import sink_kinds, source_labels
from .provenance_models import (
    AssetAttribution,
    KnowledgeGraphEdge,
    KnowledgeGraphNode,
    RelationshipNature,
)

SEVERITY_RANK = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1, "None": 0}
CODE_SYMBOL_KINDS = {
    SymbolKind.MODULE,
    SymbolKind.CLASS,
    SymbolKind.FUNCTION,
    SymbolKind.METHOD,
    SymbolKind.NESTED_FUNCTION,
}
CONFIG_OWNED_TYPES = {"skill", "plugin", "deployment", "dependency", "package"}


def _id(prefix: str, *parts: object) -> str:
    raw = "|".join(str(value) for value in parts)
    return f"{prefix}-{hashlib.sha256(raw.encode()).hexdigest()[:20].upper()}"


class ProvenanceGraphBuilder:
    """Build an evidence-backed code, asset, and security knowledge graph."""

    def __init__(self, result: ScanResult):
        self.result = result
        self.session = result.code_intelligence
        self.root = self.session.root if self.session is not None else Path(result.scan.root).resolve()
        repository_identity = result.scan.git_remote or Path(result.scan.root).name
        self.repo_id = _id("REPO", repository_identity)
        self.nodes: dict[str, KnowledgeGraphNode] = {}
        self.edges: dict[str, KnowledgeGraphEdge] = {}
        self.entities = {entity.entity_id: entity for entity in result.inventory}
        self.owners_by_symbol: dict[str, dict[str, tuple[str, str, str]]] = defaultdict(dict)
        self.incoming_calls: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
        self.call_nodes_by_location: dict[tuple[str, int], list[str]] = defaultdict(list)
        self._base_built = False

    def _relative(self, value: str | Path) -> str:
        path = Path(value)
        candidate = path if path.is_absolute() else self.root / path
        try:
            return candidate.resolve().relative_to(self.root).as_posix()
        except (OSError, ValueError):
            return path.as_posix()

    def _absolute(self, value: str | Path) -> Path:
        path = Path(value)
        return path.resolve() if path.is_absolute() else (self.root / path).resolve()

    def _location_evidence(
        self,
        file: str,
        line: int,
        *,
        column: int = 0,
        symbol: str = "",
        detail: str = "",
        edge_id: str = "",
    ) -> dict[str, Any]:
        evidence: dict[str, Any] = {"line": max(1, line)}
        if file:
            evidence["file"] = self._relative(file)
        if column:
            evidence["column"] = column
        if symbol:
            evidence["symbol"] = symbol
        if detail:
            evidence["detail"] = detail
        if edge_id:
            evidence["edge_id"] = edge_id
        return evidence

    @staticmethod
    def _best_confidence(values: Iterable[str]) -> str:
        rank = {"unresolved": 0, "low": 1, "medium": 2, "high": 3, "exact": 4, "deterministic": 4}
        return max(values, key=lambda value: rank.get(value, 0), default="unresolved")

    def _add_node(self, node: KnowledgeGraphNode) -> None:
        self.nodes.setdefault(node.node_id, node)

    def _add_edge(
        self,
        source: str,
        target: str,
        relation: str,
        relationship_type: RelationshipNature,
        confidence: str,
        derivation_method: str,
        evidence: list[dict[str, Any]],
        *,
        finding_ids: list[str] | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> str:
        edge_id = _id("EDGE", source, relation, target)
        normalized_evidence = evidence or [{"detail": f"derived by {derivation_method}"}]
        existing = self.edges.get(edge_id)
        if existing is not None:
            for item in normalized_evidence:
                if item not in existing.evidence:
                    existing.evidence.append(item)
            for finding_id in finding_ids or []:
                if finding_id not in existing.finding_ids:
                    existing.finding_ids.append(finding_id)
            existing.attributes.update(attributes or {})
            existing.confidence = self._best_confidence((existing.confidence, confidence))
            if relationship_type is RelationshipNature.EXPLICIT_DIRECT:
                existing.relationship_type = relationship_type
            return edge_id
        self.edges[edge_id] = KnowledgeGraphEdge(
            edge_id,
            source,
            target,
            relation,
            relationship_type,
            confidence,
            derivation_method,
            normalized_evidence,
            list(finding_ids or []),
            dict(attributes or {}),
        )
        return edge_id

    def _build_repository(self) -> None:
        self._add_node(KnowledgeGraphNode(
            self.repo_id,
            "repository",
            "asset",
            "repository",
            self.result.scan.git_remote or self.result.scan.root,
            {},
            {"finding_count": len(self.result.findings), "max_severity": "None"},
            {"branch": self.result.scan.git_branch, "remote": self.result.scan.git_remote},
            {"version": {
                "value": self.result.scan.git_commit[:12] if self.result.scan.git_commit else "workspace",
                "scheme": "git-commit" if self.result.scan.git_commit else "workspace",
                "source": "git" if self.result.scan.git_commit else "workspace",
            }},
        ))

    @staticmethod
    def _asset_node_class(entity_type: str) -> str:
        if entity_type in {"dependency", "package", "model_artifact", "service", "provider"}:
            return "supply_chain"
        return "asset"

    def _build_assets(self) -> None:
        for entity in self.result.inventory:
            source = {"file": entity.file, "line": entity.line}
            self._add_node(KnowledgeGraphNode(
                entity.entity_id,
                "asset",
                self._asset_node_class(entity.entity_type),
                entity.entity_type,
                entity.name,
                source,
                {"finding_count": 0, "direct_finding_count": 0, "transitive_finding_count": 0, "max_severity": "None", "finding_ids": []},
                entity.attributes,
                {
                    "category": entity.category,
                    "qualified_name": entity.qualified_name,
                    "framework": {"name": entity.framework, "version": entity.framework_version},
                    "version": {"id": entity.version_id, "value": entity.version, "scheme": entity.version_scheme, "source": entity.version_source, "evidence": entity.version_evidence},
                    "package": {"name": entity.package_name, "version": entity.package_version},
                    "content_digest": f"sha256:{entity.content_hash}" if entity.content_hash else "",
                },
            ))
            evidence = [self._location_evidence(entity.file, entity.line, symbol=entity.qualified_name)]
            self._add_edge(
                self.repo_id,
                entity.entity_id,
                "DEFINES",
                RelationshipNature.EXPLICIT_DIRECT,
                "exact",
                "inventory-discovery",
                evidence,
                attributes={"resolution": "exact"},
            )

        packages = {package.package_id: package for package in self.result.packages}
        for vulnerability in self.result.vulnerabilities:
            package = packages.get(vulnerability.affected_package_id)
            evidence = package.source_evidence[0] if package and package.source_evidence else {}
            self._add_node(KnowledgeGraphNode(
                vulnerability.vulnerability_id,
                "finding",
                "security",
                "known_vulnerability",
                vulnerability.canonical_id,
                {
                    "file": str(evidence.get("file", "")),
                    "line": int(evidence.get("line", 1)),
                },
                {
                    "severity": vulnerability.severity,
                    "affected_version_status": vulnerability.affected_version_status,
                    "reachability": vulnerability.reachability,
                    "exploitability": vulnerability.exploitability,
                },
                vulnerability.to_dict(),
            ))

        for relationship in self.result.relationships:
            if relationship.source_id not in self.nodes or relationship.target_id not in self.nodes:
                continue
            evidence = [
                self._location_evidence(
                    str(item.get("file", "")),
                    int(item.get("line", relationship.evidence_line)),
                    symbol=str(item.get("symbol", "")),
                    detail=str(item.get("detail", "")),
                )
                for item in relationship.source_evidence
            ]
            if not evidence and relationship.evidence_file:
                evidence = [self._location_evidence(relationship.evidence_file, relationship.evidence_line)]
            nature = {
                "inferred": RelationshipNature.INFERRED,
                "transitive/derived": RelationshipNature.TRANSITIVE_DERIVED,
            }.get(relationship.relationship_type, RelationshipNature.EXPLICIT_DIRECT)
            self._add_edge(
                relationship.source_id,
                relationship.target_id,
                relationship.relation,
                nature,
                relationship.confidence,
                relationship.derivation_method,
                evidence,
                attributes=relationship.attributes,
            )

    def _symbol_source(self, symbol: CodeSymbol) -> dict[str, Any]:
        start, end = symbol.source_range.start, symbol.source_range.end
        end_line = end.line
        if symbol.kind is SymbolKind.MODULE and self.session is not None:
            module = self.session.index.modules.get(symbol.module)
            if module is not None:
                end_line = max(1, len(module.lines))
        return {
            "file": self._relative(start.file),
            "line": start.line,
            "column": start.column,
            "end_line": end_line,
            "end_column": end.column,
        }

    def _build_code_symbols(self) -> None:
        if self.session is None:
            return
        for symbol in sorted(self.session.index.symbols_by_id.values(), key=lambda item: item.symbol_id):
            if symbol.kind not in CODE_SYMBOL_KINDS:
                continue
            source = self._symbol_source(symbol)
            self._add_node(KnowledgeGraphNode(
                symbol.symbol_id,
                "code",
                "code",
                symbol.kind.value,
                symbol.qualified_name,
                source,
                {"finding_count": 0, "max_severity": "None"},
                {"decorators": list(symbol.decorators), "parameters": list(symbol.parameters), "async": symbol.is_async},
                {"qualified_name": symbol.qualified_name, "module": symbol.module, "parent_symbol_id": symbol.parent_symbol_id},
            ))
            parent_id = symbol.parent_symbol_id if symbol.parent_symbol_id in self.nodes else self.repo_id
            evidence = [self._location_evidence(source["file"], source["line"], column=source["column"], symbol=symbol.qualified_name)]
            self._add_edge(
                parent_id,
                symbol.symbol_id,
                "DEFINES",
                RelationshipNature.EXPLICIT_DIRECT,
                "exact",
                "python-symbol-index",
                evidence,
                attributes={"symbol_kind": symbol.kind.value},
            )

    def _call_evidence(self, call_site: Any) -> list[dict[str, Any]]:
        start = call_site.source_range.start
        return [self._location_evidence(start.file, start.line, column=start.column, symbol=call_site.callee_expression)]

    def _build_calls(self) -> None:
        if self.session is None:
            return
        call_sites = {site.call_site_id: site for site in self.session.call_sites}
        resolved_sites = {edge.call_site_id for edge in self.session.call_edges}
        for call_edge in self.session.call_edges:
            site = call_sites[call_edge.call_site_id]
            if call_edge.caller_symbol_id not in self.nodes or call_edge.callee_symbol_id not in self.nodes:
                continue
            nature = RelationshipNature.EXPLICIT_DIRECT if call_edge.confidence is ResolutionConfidence.EXACT else RelationshipNature.INFERRED
            edge_id = self._add_edge(
                call_edge.caller_symbol_id,
                call_edge.callee_symbol_id,
                "CALLS",
                nature,
                call_edge.confidence.value,
                call_edge.resolution_method,
                self._call_evidence(site),
                attributes={"call_site_id": call_edge.call_site_id, "callee_expression": site.callee_expression},
            )
            self.incoming_calls[call_edge.callee_symbol_id].append((call_edge.caller_symbol_id, edge_id, call_edge.confidence.value))

        for site in self.session.call_sites:
            sources = sorted(source_labels(site.callee_expression))
            sinks = sorted(sink_kinds(site.callee_expression))
            relevant = site.call_site_id not in resolved_sites or sources or sinks
            if not relevant or site.caller_symbol_id not in self.nodes:
                continue
            subtype = "external_call" if site.call_site_id not in resolved_sites else "api_call"
            start = site.source_range.start
            source = {"file": self._relative(start.file), "line": start.line, "column": start.column}
            self._add_node(KnowledgeGraphNode(
                site.call_site_id,
                "code",
                "code",
                subtype,
                site.callee_expression,
                source,
                {"finding_count": 0, "max_severity": "None"},
                {
                    "caller_symbol_id": site.caller_symbol_id,
                    "argument_count": site.argument_count,
                    "keyword_names": list(site.keyword_names),
                    "source_labels": sources,
                    "sink_kinds": sinks,
                    "resolution": "unresolved" if site.call_site_id not in resolved_sites else "resolved",
                },
            ))
            self.call_nodes_by_location[(source["file"], source["line"])].append(site.call_site_id)
            self._add_edge(
                site.caller_symbol_id,
                site.call_site_id,
                "CALLS",
                RelationshipNature.EXPLICIT_DIRECT,
                "exact",
                "python-call-site",
                self._call_evidence(site),
                attributes={"external_or_api_call": True},
            )

    def _build_data_flow(self) -> None:
        if self.session is None:
            return
        by_qualname = {
            symbol.qualified_name: symbol.symbol_id
            for symbol in self.session.index.symbols_by_id.values()
            if symbol.kind in CODE_SYMBOL_KINDS
        }
        for flow in self.session.data_flow_edges:
            source_id = flow.source.owner_symbol_id if flow.source is not None else ""
            target_id = flow.target.owner_symbol_id
            relation = "PASSES_DATA_TO"
            if flow.operation == "return":
                if len(flow.context) < 2:
                    continue
                source_id = target_id
                target_id = by_qualname.get(flow.context[-2], "")
                relation = "RETURNS_TO"
            if not source_id or not target_id or source_id == target_id:
                continue
            if source_id not in self.nodes or target_id not in self.nodes:
                continue
            start = flow.source_range.start
            self._add_edge(
                source_id,
                target_id,
                relation,
                RelationshipNature.TRANSITIVE_DERIVED,
                flow.confidence.value,
                f"abstract-data-flow:{flow.operation}",
                [self._location_evidence(start.file, start.line, column=start.column, detail=flow.operation)],
                attributes={"operation": flow.operation, "context": list(flow.context)},
            )

    def _symbols_for_entity(self, entity: Any) -> list[tuple[CodeSymbol, RelationshipNature, str, str]]:
        if self.session is None or entity.entity_type in CONFIG_OWNED_TYPES:
            return []
        index = self.session.index
        exact = index.symbols.get(entity.qualified_name)
        if exact is not None and exact.kind in CODE_SYMBOL_KINDS:
            matches = [(exact, RelationshipNature.EXPLICIT_DIRECT, "exact", "qualified-name-ownership")]
            if exact.kind is SymbolKind.CLASS:
                for symbol in index.symbols_by_id.values():
                    if symbol.kind in {SymbolKind.METHOD, SymbolKind.NESTED_FUNCTION} and symbol.qualified_name.startswith(f"{exact.qualified_name}."):
                        matches.append((symbol, RelationshipNature.INFERRED, "high", "class-member-ownership"))
            return matches
        return []

    def _build_ownership(self) -> None:
        if self.session is None:
            return
        for entity in self.result.inventory:
            matches = self._symbols_for_entity(entity)
            for symbol, nature, confidence, method in matches:
                source = self._symbol_source(symbol)
                self._add_edge(
                    entity.entity_id,
                    symbol.symbol_id,
                    "IMPLEMENTED_BY",
                    nature,
                    confidence,
                    method,
                    [self._location_evidence(source["file"], source["line"], symbol=symbol.qualified_name)],
                    attributes={"ownership": True},
                )
                self.owners_by_symbol[symbol.symbol_id][entity.entity_id] = (nature.value, confidence, method)
            if matches:
                continue
            location = (self._relative(entity.file), entity.line)
            for call_node_id in self.call_nodes_by_location.get(location, []):
                self._add_edge(
                    entity.entity_id,
                    call_node_id,
                    "IMPLEMENTED_BY",
                    RelationshipNature.EXPLICIT_DIRECT,
                    "exact",
                    "constructor-call-ownership",
                    [self._location_evidence(entity.file, entity.line, symbol=entity.qualified_name)],
                    attributes={"ownership": True},
                )

    def _build_base(self) -> None:
        if self._base_built:
            return
        self._build_repository()
        self._build_code_symbols()
        self._build_calls()
        self._build_assets()
        self._build_data_flow()
        self._build_ownership()
        self._base_built = True

    def _containing_symbol(self, file: str, line: int) -> CodeSymbol | None:
        if self.session is None:
            return None
        resolved = self._absolute(file)
        candidates: list[CodeSymbol] = []
        modules: list[CodeSymbol] = []
        for symbol in self.session.index.symbols_by_id.values():
            if self._absolute(symbol.source_range.start.file) != resolved:
                continue
            if symbol.kind not in CODE_SYMBOL_KINDS:
                continue
            if symbol.kind is SymbolKind.MODULE:
                modules.append(symbol)
                continue
            if symbol.source_range.start.line <= line <= symbol.source_range.end.line:
                candidates.append(symbol)
        if candidates:
            return min(candidates, key=lambda item: (item.source_range.end.line - item.source_range.start.line, -len(item.qualified_name)))
        return modules[0] if modules else None

    def _reverse_call_owners(self, starts: list[str]) -> tuple[dict[str, list[str]], dict[str, str]]:
        paths: dict[str, list[str]] = {}
        confidences: dict[str, str] = {}
        queue = deque((symbol_id, [], "exact") for symbol_id in starts)
        visited = set(starts)
        while queue:
            symbol_id, reverse_path, path_confidence = queue.popleft()
            owners = self.owners_by_symbol.get(symbol_id, {})
            if owners:
                for owner_id, (_, owner_confidence, _) in owners.items():
                    implementation_edge = _id("EDGE", owner_id, "IMPLEMENTED_BY", symbol_id)
                    paths.setdefault(owner_id, [implementation_edge, *reversed(reverse_path)])
                    confidences[owner_id] = min(
                        (path_confidence, owner_confidence),
                        key=lambda value: {"unresolved": 0, "low": 1, "medium": 2, "high": 3, "exact": 4}.get(value, 0),
                    )
                continue
            for caller_id, edge_id, edge_confidence in self.incoming_calls.get(symbol_id, []):
                if caller_id in visited:
                    continue
                visited.add(caller_id)
                combined = min(
                    (path_confidence, edge_confidence),
                    key=lambda value: {"unresolved": 0, "low": 1, "medium": 2, "high": 3, "exact": 4}.get(value, 0),
                )
                queue.append((caller_id, [*reverse_path, edge_id], combined))
        return paths, confidences

    def _transitive_assets(self, direct_assets: list[str]) -> tuple[list[str], dict[str, list[str]]]:
        incoming: dict[str, list[Any]] = defaultdict(list)
        for relationship in self.result.relationships:
            incoming[relationship.target_id].append(relationship)
        direct = set(direct_assets)
        paths: dict[str, list[str]] = {}
        queue = deque((asset_id, []) for asset_id in direct_assets if asset_id in self.entities)
        visited = set(direct_assets)
        while queue:
            asset_id, path_to_direct = queue.popleft()
            for relationship in incoming.get(asset_id, []):
                upstream = relationship.source_id
                if upstream in visited:
                    continue
                visited.add(upstream)
                edge_id = _id("EDGE", relationship.source_id, relationship.relation, relationship.target_id)
                path = [edge_id, *path_to_direct]
                if upstream not in direct:
                    paths[upstream] = path
                queue.append((upstream, path))
        return sorted(paths), paths

    def _attribution_for(self, finding: Any) -> AssetAttribution:
        source_symbols: list[str] = []
        sink_symbols: list[str] = []
        all_symbols: list[str] = []
        attribution_evidence: list[dict[str, Any]] = []

        containing_id = str(finding.engine_metadata.get("containing_symbol_id", ""))
        if containing_id and containing_id in self.nodes:
            all_symbols.append(containing_id)
            sink_symbols.append(containing_id)
        for evidence in finding.evidence:
            symbol = self._containing_symbol(evidence.file, evidence.line)
            if symbol is None:
                continue
            if symbol.symbol_id not in all_symbols:
                all_symbols.append(symbol.symbol_id)
            if evidence.kind == "source" and symbol.symbol_id not in source_symbols:
                source_symbols.append(symbol.symbol_id)
            if evidence.kind in {"sink", "structural", "ast", "config", "permission"} and symbol.symbol_id not in sink_symbols:
                sink_symbols.append(symbol.symbol_id)
            attribution_evidence.append(self._location_evidence(evidence.file, evidence.line, symbol=symbol.qualified_name, detail=evidence.kind))
        if not sink_symbols:
            location_symbol = self._containing_symbol(finding.file, finding.line)
            if location_symbol is not None:
                sink_symbols.append(location_symbol.symbol_id)
                if location_symbol.symbol_id not in all_symbols:
                    all_symbols.append(location_symbol.symbol_id)

        direct: dict[str, tuple[str, str]] = {}
        ownership_paths: dict[str, list[str]] = {}
        for symbol_id in sink_symbols:
            for owner_id, (_, confidence, method) in self.owners_by_symbol.get(symbol_id, {}).items():
                direct.setdefault(owner_id, (confidence, method))
                ownership_paths.setdefault(owner_id, [_id("EDGE", owner_id, "IMPLEMENTED_BY", symbol_id)])
        method = "symbol-ownership"
        if not direct and sink_symbols:
            reverse_paths, reverse_confidence = self._reverse_call_owners(sink_symbols)
            for owner_id, path in reverse_paths.items():
                direct[owner_id] = (reverse_confidence.get(owner_id, "medium"), "reverse-call-ownership")
                ownership_paths[owner_id] = path
            if direct:
                method = "reverse-call-ownership"

        if not direct:
            for symbol_id in all_symbols:
                for owner_id, (_, confidence, owner_method) in self.owners_by_symbol.get(symbol_id, {}).items():
                    direct.setdefault(owner_id, (confidence, owner_method))
                    ownership_paths.setdefault(owner_id, [_id("EDGE", owner_id, "IMPLEMENTED_BY", symbol_id)])
            if direct:
                method = "evidence-symbol-ownership"

        if not direct:
            file_assets = [
                entity.entity_id
                for entity in self.result.inventory
                if entity.entity_type in CONFIG_OWNED_TYPES
                and self._relative(entity.file) == self._relative(finding.file)
            ]
            for asset_id in file_assets:
                direct[asset_id] = ("high", "declared-source-file-ownership")
            if direct:
                method = "declared-source-file-ownership"

        direct_assets = sorted(direct) or [self.repo_id]
        transitive_assets, transitive_paths = self._transitive_assets(direct_assets)
        for asset_id, path in transitive_paths.items():
            direct_target = self.edges[path[-1]].target if path and path[-1] in self.edges else ""
            ownership_paths[asset_id] = [*path, *ownership_paths.get(direct_target, [])]
        confidence = self._best_confidence(value[0] for value in direct.values()) if direct else "exact"
        return AssetAttribution(
            directly_affected_assets=direct_assets,
            transitively_affected_assets=transitive_assets,
            source_symbol_ids=source_symbols,
            sink_symbol_ids=sink_symbols,
            ownership_paths=ownership_paths,
            confidence=confidence,
            derivation_method=method if direct else "repository-fallback",
            evidence=attribution_evidence or [self._location_evidence(finding.file, finding.line, detail="finding location")],
        )

    def attribute_findings(self) -> None:
        self._build_base()
        for finding in self.result.findings:
            attribution = self._attribution_for(finding)
            finding.directly_affected_assets = attribution.directly_affected_assets
            finding.transitively_affected_assets = attribution.transitively_affected_assets
            finding.attribution = attribution.to_dict()

    def _finding_evidence(self, finding: Any) -> list[dict[str, Any]]:
        return [self._location_evidence(finding.file, finding.line, detail=finding.rule_id)]

    def _build_findings(self) -> list[dict[str, Any]]:
        attack_paths: list[dict[str, Any]] = []
        direct_risk: dict[str, list[Any]] = defaultdict(list)
        transitive_risk: dict[str, list[Any]] = defaultdict(list)
        self.attribute_findings()

        for finding in self.result.findings:
            finding_id = finding.finding_id or _id("FINDING", finding.rule_id, finding.file, finding.line)
            self._add_node(KnowledgeGraphNode(
                finding_id,
                "finding",
                "security",
                finding.category or "static_finding",
                finding.title or finding.name,
                {"file": finding.file, "line": finding.line},
                {"severity": finding.severity, "rule_id": finding.rule_id, "analysis_type": finding.analysis_type},
                {
                    "description": finding.description,
                    "remediation": finding.remediation,
                    "fingerprint": finding.fingerprint,
                    "mappings": finding.mappings,
                    "cwe": finding.cwe,
                    "engine_metadata": finding.engine_metadata,
                    "directly_affected_assets": finding.directly_affected_assets,
                    "transitively_affected_assets": finding.transitively_affected_assets,
                    "attribution": finding.attribution,
                },
                {"version": {"value": finding.rule_version, "scheme": "rule-version", "source": "rule_catalog"}},
            ))

            direct_edge_ids: dict[str, str] = {}
            for asset_id in finding.directly_affected_assets:
                if asset_id not in self.nodes:
                    continue
                direct_risk[asset_id].append(finding)
                direct_edge_ids[asset_id] = self._add_edge(
                    asset_id,
                    finding_id,
                    "HAS_FINDING",
                    RelationshipNature.EXPLICIT_DIRECT,
                    finding.attribution.get("confidence", "exact"),
                    finding.attribution.get("derivation_method", "symbol-ownership"),
                    list(finding.attribution.get("evidence") or self._finding_evidence(finding)),
                    finding_ids=[finding_id],
                    attributes={"rule_id": finding.rule_id, "attribution": "direct"},
                )
            for asset_id in finding.transitively_affected_assets:
                if asset_id not in self.nodes:
                    continue
                transitive_risk[asset_id].append(finding)
                path_edges = finding.attribution.get("ownership_paths", {}).get(asset_id, [])
                source_evidence = [
                    {"edge_id": edge_id, "detail": "upstream ownership/dependency path"}
                    for edge_id in path_edges
                ] or self._finding_evidence(finding)
                self._add_edge(
                    asset_id,
                    finding_id,
                    "HAS_FINDING",
                    RelationshipNature.TRANSITIVE_DERIVED,
                    "high" if path_edges else "medium",
                    "upstream-asset-propagation",
                    source_evidence,
                    finding_ids=[finding_id],
                    attributes={"rule_id": finding.rule_id, "attribution": "transitive", "path_edge_ids": path_edges},
                )

            evidence_node_ids: list[str] = []
            evidence_edge_ids: list[str] = []
            previous_id = ""
            previous_evidence: dict[str, Any] | None = None
            for index, evidence in enumerate(finding.evidence):
                evidence_id = _id("EVIDENCE", finding_id, index, evidence.kind, evidence.file, evidence.line, evidence.symbol, evidence.label)
                evidence_node_ids.append(evidence_id)
                source = {"file": evidence.file, "line": evidence.line, "symbol": evidence.symbol}
                self._add_node(KnowledgeGraphNode(
                    evidence_id,
                    "evidence",
                    "security",
                    evidence.kind,
                    evidence.label,
                    source,
                    {"severity": finding.severity},
                    {"detail": evidence.detail, "finding_id": finding_id, "sequence": index},
                ))
                current_evidence = self._location_evidence(evidence.file, evidence.line, symbol=evidence.symbol, detail=evidence.detail or evidence.label)
                if not previous_id:
                    evidence_edge_ids.append(self._add_edge(
                        finding_id,
                        evidence_id,
                        "HAS_EVIDENCE",
                        RelationshipNature.EXPLICIT_DIRECT,
                        "exact",
                        "finding-evidence-chain",
                        [current_evidence],
                        finding_ids=[finding_id],
                        attributes={"sequence": index},
                    ))
                else:
                    evidence_edge_ids.append(self._add_edge(
                        previous_id,
                        evidence_id,
                        "EVIDENCE_FLOW",
                        RelationshipNature.TRANSITIVE_DERIVED,
                        finding.confidence,
                        "ordered-analyzer-evidence",
                        [previous_evidence or current_evidence, current_evidence],
                        finding_ids=[finding_id],
                        attributes={"sequence": index},
                    ))
                symbol = self._containing_symbol(evidence.file, evidence.line)
                if symbol is not None and symbol.symbol_id in self.nodes:
                    self._add_edge(
                        evidence_id,
                        symbol.symbol_id,
                        "OBSERVED_IN",
                        RelationshipNature.EXPLICIT_DIRECT,
                        "exact",
                        "source-range-containment",
                        [current_evidence],
                        finding_ids=[finding_id],
                        attributes={"evidence_kind": evidence.kind},
                    )
                previous_id = evidence_id
                previous_evidence = current_evidence

            primary_direct = next((asset_id for asset_id in finding.directly_affected_assets if asset_id in direct_edge_ids), self.repo_id)
            upstream_candidates = [
                asset_id for asset_id in finding.transitively_affected_assets
                if finding.attribution.get("ownership_paths", {}).get(asset_id)
            ]
            path_owner = primary_direct
            if upstream_candidates:
                path_owner = max(
                    upstream_candidates,
                    key=lambda asset_id: (
                        self.entities.get(asset_id).entity_type in {"agent", "sub_agent", "orchestrator", "agent_proxy"} if asset_id in self.entities else False,
                        len(finding.attribution["ownership_paths"][asset_id]),
                        asset_id,
                    ),
                )
            ownership_edge_ids = list(finding.attribution.get("ownership_paths", {}).get(path_owner, []))
            path_node_ids = [path_owner]
            valid_ownership_edges: list[str] = []
            current_node = path_owner
            for edge_id in ownership_edge_ids:
                edge = self.edges.get(edge_id)
                if edge is None or edge.source != current_node:
                    break
                valid_ownership_edges.append(edge_id)
                path_node_ids.append(edge.target)
                current_node = edge.target

            terminal_finding_edge = direct_edge_ids.get(primary_direct)
            current = self.nodes.get(current_node)
            if current is not None and current.kind == "code":
                terminal_finding_edge = self._add_edge(
                    current_node,
                    finding_id,
                    "HAS_FINDING",
                    RelationshipNature.EXPLICIT_DIRECT,
                    finding.attribution.get("confidence", "exact"),
                    "finding-sink-symbol",
                    list(finding.attribution.get("evidence") or self._finding_evidence(finding)),
                    finding_ids=[finding_id],
                    attributes={"rule_id": finding.rule_id, "attribution": "code-symbol"},
                )
            path_node_ids.append(finding_id)
            path_node_ids.extend(evidence_node_ids)
            path_edge_ids = [*valid_ownership_edges]
            if terminal_finding_edge:
                path_edge_ids.append(terminal_finding_edge)
            path_edge_ids.extend(evidence_edge_ids)
            attack_paths.append({
                "path_id": _id("PATH", finding_id),
                "finding_id": finding_id,
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "title": finding.title or finding.name,
                "entry_node_id": evidence_node_ids[0] if evidence_node_ids else primary_direct,
                "impact_node_id": evidence_node_ids[-1] if evidence_node_ids else finding_id,
                "asset_node_id": primary_direct,
                "directly_affected_assets": finding.directly_affected_assets,
                "transitively_affected_assets": finding.transitively_affected_assets,
                "node_ids": path_node_ids,
                "edge_ids": path_edge_ids,
                "evidence_node_ids": evidence_node_ids,
                "attribution": finding.attribution,
                "explanation": finding.description or finding.message,
                "remediation": finding.remediation,
            })

        self._backfill_risk(direct_risk, transitive_risk)
        return attack_paths

    def _backfill_risk(self, direct: dict[str, list[Any]], transitive: dict[str, list[Any]]) -> None:
        for node_id in set(direct) | set(transitive):
            node = self.nodes.get(node_id)
            if node is None:
                continue
            direct_findings = {finding.finding_id: finding for finding in direct.get(node_id, [])}
            transitive_findings = {finding.finding_id: finding for finding in transitive.get(node_id, [])}
            all_findings = {**transitive_findings, **direct_findings}
            node.risk = {
                "finding_count": len(all_findings),
                "direct_finding_count": len(direct_findings),
                "transitive_finding_count": len(transitive_findings),
                "max_severity": max((finding.severity for finding in all_findings.values()), key=lambda value: SEVERITY_RANK.get(value, 0), default="None"),
                "finding_ids": sorted(all_findings),
            }

    def _build_vulnerability_paths(self) -> list[dict[str, Any]]:
        paths: list[dict[str, Any]] = []
        packages = {package.package_id: package for package in self.result.packages}
        incoming: dict[str, list[KnowledgeGraphEdge]] = defaultdict(list)
        allowed = {
            "AGENT_USES_MODEL",
            "TOOL_USES_MODEL",
            "USES_MODEL",
            "MODEL_IMPLEMENTED_WITH_PACKAGE",
            "DEPENDS_ON",
            "IMPORTS_PACKAGE",
            "IMPLEMENTED_BY",
            "CALLS",
        }
        for edge in self.edges.values():
            if edge.relation in allowed:
                incoming[edge.target].append(edge)
        for vulnerability in self.result.vulnerabilities:
            package_id = vulnerability.affected_package_id
            terminal_id = _id("EDGE", package_id, "HAS_VULNERABILITY", vulnerability.vulnerability_id)
            if terminal_id not in self.edges or package_id not in self.nodes:
                continue
            queue = deque([(package_id, [], [package_id])])
            seen = {package_id}
            best_edges: list[str] = []
            best_nodes: list[str] = [package_id]
            while queue:
                node_id, reverse_edges, reverse_nodes = queue.popleft()
                node = self.nodes.get(node_id)
                if node and node.subtype in {"agent", "sub_agent", "orchestrator", "agent_proxy", "tool", "mcp_tool"}:
                    best_edges = list(reversed(reverse_edges))
                    best_nodes = list(reversed(reverse_nodes))
                    break
                for edge in sorted(
                    incoming.get(node_id, []),
                    key=lambda item: (
                        self.nodes.get(item.source).subtype not in {"agent", "sub_agent", "orchestrator", "agent_proxy"}
                        if self.nodes.get(item.source) else True,
                        item.relation == "USES_MODEL",
                        item.edge_id,
                    ),
                ):
                    if edge.source in seen:
                        continue
                    seen.add(edge.source)
                    queue.append((edge.source, [*reverse_edges, edge.edge_id], [*reverse_nodes, edge.source]))
            package = packages.get(package_id)
            paths.append({
                "path_id": _id("PATH", vulnerability.vulnerability_id),
                "finding_id": vulnerability.vulnerability_id,
                "rule_id": vulnerability.canonical_id,
                "severity": vulnerability.severity.title(),
                "title": vulnerability.summary or f"Known vulnerability {vulnerability.canonical_id}",
                "entry_node_id": best_nodes[0],
                "impact_node_id": vulnerability.vulnerability_id,
                "asset_node_id": package_id,
                "directly_affected_assets": [package_id],
                "transitively_affected_assets": best_nodes[:-1],
                "node_ids": [*best_nodes, vulnerability.vulnerability_id],
                "edge_ids": [*best_edges, terminal_id],
                "evidence_node_ids": [],
                "attribution": {
                    "provider": vulnerability.source,
                    "package_presence": vulnerability.package_presence,
                    "affected_version_status": vulnerability.affected_version_status,
                    "reachability": vulnerability.reachability,
                    "exploitability": vulnerability.exploitability,
                    "purl": package.purl if package else "",
                },
                "explanation": vulnerability.details or vulnerability.summary,
                "remediation": [f"Upgrade to a fixed version: {', '.join(vulnerability.fixed_versions)}"] if vulnerability.fixed_versions else [],
            })
            package_node = self.nodes.get(package_id)
            if package_node is not None:
                vulnerability_ids = set(package_node.risk.get("vulnerability_ids", []))
                vulnerability_ids.add(vulnerability.vulnerability_id)
                package_node.risk.update({
                    "vulnerability_count": len(vulnerability_ids),
                    "vulnerability_ids": sorted(vulnerability_ids),
                    "affected_version_status": vulnerability.affected_version_status,
                    "reachability": vulnerability.reachability,
                    "exploitability": vulnerability.exploitability,
                })
        return paths

    def build(self) -> dict[str, Any]:
        self._build_base()
        attack_paths = self._build_findings()
        attack_paths.extend(self._build_vulnerability_paths())
        node_dicts = [node.to_dict() for node in self.nodes.values()]
        edge_dicts = [edge.to_dict() for edge in self.edges.values()]
        asset_types = Counter(node.subtype for node in self.nodes.values() if node.kind == "asset")
        node_classes = Counter(node.node_class for node in self.nodes.values())
        relations = Counter(edge.relation for edge in self.edges.values())
        relationship_types = Counter(edge.relationship_type.value for edge in self.edges.values())
        return {
            "schema": "agentguard-provenance-graph/1.0",
            "scan": {
                "scan_id": self.result.scan.scan_id,
                "repository": self.result.scan.root,
                "repository_node_id": self.repo_id,
                "git_commit": self.result.scan.git_commit,
                "git_branch": self.result.scan.git_branch,
            },
            "summary": {
                "nodes": len(node_dicts),
                "edges": len(edge_dicts),
                "attack_paths": len(attack_paths),
                "asset_types": dict(asset_types),
                "node_classes": dict(node_classes),
                "relationship_types": dict(relations),
                "relationship_evidence_types": dict(relationship_types),
            },
            "nodes": node_dicts,
            "edges": edge_dicts,
            "attack_paths": attack_paths,
            "ui_hints": {
                "default_node_label": "label",
                "group_by": "node_class",
                "severity_field": "risk.max_severity",
                "edge_label": "relation",
                "edge_confidence_field": "confidence",
                "edge_derivation_field": "relationship_type",
                "expand_evidence_on_demand": True,
                "distinguish_direct_and_transitive_findings": True,
            },
        }


def attribute_findings(result: ScanResult) -> None:
    """Attach direct/transitive asset attribution before result serialization."""

    ProvenanceGraphBuilder(result).attribute_findings()


def generate_provenance_graph(result: ScanResult) -> dict[str, Any]:
    """Create graph 1.0 with additive Milestone 2 evidence semantics."""

    return ProvenanceGraphBuilder(result).build()
