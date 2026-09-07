from __future__ import annotations

import hashlib
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .code_intelligence import CodeIntelligenceSession
from .config_analyzer import ConfigAnalyzer
from .contracts import ScanError, ScanMetadata, ScanMetrics, ScanRequest, ScanResult
from .enrichment import enrich_findings
from .file_inventory import discover_repository_files
from .inventory import InventoryDiscoverer
from .model_inventory import build_model_inventory
from .models import Finding, InventoryEntity, Relationship
from .package_inventory import PackageInventory, normalize_package_name
from .project_analyzer import ProjectPythonAnalyzer
from .provenance import attribute_findings
from .rules import RuleStore
from .skill_analyzer import SkillSecurityAnalyzer
from .treesitter_analyzer import TreeSitterAnalyzer
from .vulnerabilities import (
    NETWORK_ERRORS,
    CachedVulnerabilityProvider,
    OSVVulnerabilityProvider,
    enrich_packages,
)

DEFAULT_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".yaml", ".yml", ".json", ".toml", ".md", ".tf"}

def bundled_rules_dir() -> Path:
    return Path(__file__).resolve().parent / "rules" / "builtin"


class Scanner:
    """Persistence-free AgentGuard scanner core.

    Detection engines are the existing AgentGuard analyzers. The coordinator only
    discovers files, invokes engines, normalizes/enriches output, and returns a
    versioned ScanResult. It has no authentication, HTTP, database, or UI concerns.
    """

    def __init__(self, request: ScanRequest):
        self.request = request
        self.root = request.root.resolve()
        rules_dir = request.rules_dir or bundled_rules_dir()
        rules = RuleStore(rules_dir).load()
        self.rules = [rule for rule in rules if not request.rule_ids or rule.id in request.rule_ids]
        self.native_rules = [rule for rule in self.rules if rule.engine == "agentguard"]
        self.skill_rules = [rule for rule in self.rules if rule.engine == "agentguard-skill"]

    def files(self, repository_paths: list[Path] | None = None) -> list[Path]:
        candidates = repository_paths if repository_paths is not None else discover_repository_files(self.root)
        return [
            path for path in candidates
            if path.suffix.lower() in DEFAULT_EXTENSIONS or path.name in {"Dockerfile", "SKILL.md"}
        ]

    def scan(self) -> ScanResult:
        started = time.perf_counter()
        now = datetime.now(timezone.utc).isoformat()
        metadata = ScanMetadata(str(uuid.uuid4()), str(self.root), now)
        result = ScanResult(metadata, metrics=ScanMetrics())
        repository_paths = discover_repository_files(self.root)
        paths = self.files(repository_paths)
        result.metrics.files_scanned = len(paths)

        python_paths = [path for path in paths if path.suffix.lower() == ".py"]
        code_session = None
        if python_paths:
            try:
                code_session = CodeIntelligenceSession.from_files(self.root, python_paths)
                result.code_intelligence = code_session
                for path, error in code_session.index.parse_errors:
                    result.errors.append(ScanError("python-parser", str(path), str(error)))
            except (OSError, ValueError, RuntimeError) as exc:
                result.errors.append(ScanError("code-intelligence", str(self.root), str(exc)))

        inventory_discoverer = InventoryDiscoverer(self.root, code_session)
        git = inventory_discoverer.git_context()
        metadata.git_commit = git.get("commit", "")
        metadata.git_branch = git.get("branch", "")
        metadata.git_remote = git.get("remote", "")

        if self.request.include_inventory:
            try:
                result.inventory, result.relationships = inventory_discoverer.discover(repository_paths)
            except (OSError, ValueError, SyntaxError, RuntimeError) as exc:
                result.errors.append(ScanError("inventory", str(self.root), str(exc)))
            try:
                result.packages, package_relationships = PackageInventory(self.root, repository_paths).discover()
                for package in result.packages:
                    evidence = package.source_evidence[0] if package.source_evidence else {}
                    content_hash = hashlib.sha256((package.purl or f"{package.ecosystem}:{package.name}:{package.version}").encode()).hexdigest()
                    entity = InventoryEntity(
                        package.package_id,
                        "package",
                        package.name,
                        str(evidence.get("file", "")),
                        int(evidence.get("line", 1)),
                        content_hash=content_hash,
                        attributes={
                            "ecosystem": package.ecosystem,
                            "normalized_name": package.normalized_name,
                            "purl": package.purl,
                            "dependency_type": package.dependency_type,
                            "manifest_origins": package.manifest_origins,
                            "lockfile_origins": package.lockfile_origins,
                            "dependency_path": package.dependency_path,
                            "licenses": package.licenses,
                            "resolved": package.resolved,
                        },
                        qualified_name=f"package.{package.ecosystem.lower()}.{package.normalized_name}",
                        category="dependency",
                        version=package.version,
                        version_source="lockfile" if package.lockfile_origins else "dependency_manifest",
                        package_name=package.name,
                        package_version=package.version,
                        detection_source="lockfile" if package.lockfile_origins else "dependency_manifest",
                        bom_ref=package.package_id,
                        version_scheme="resolved-package" if package.resolved else "declared-constraint",
                        version_evidence={"manifest_origins": package.manifest_origins, "lockfile_origins": package.lockfile_origins},
                    ).finalize(self.root)
                    result.inventory.append(entity)
                result.relationships.extend(package_relationships)
                if code_session is not None:
                    packages_by_import = {}
                    for package in result.packages:
                        if package.ecosystem != "PyPI":
                            continue
                        packages_by_import.setdefault(package.normalized_name, package)
                    import_relationships = []
                    for module in code_session.index.modules.values():
                        if module.symbol is None:
                            continue
                        for imported in module.imports.values():
                            import_root = imported.split(".", 1)[0]
                            package = packages_by_import.get(normalize_package_name(import_root, "PyPI"))
                            if package is None:
                                continue
                            import_relationships.append(Relationship(
                                module.symbol.symbol_id,
                                "IMPORTS_PACKAGE",
                                package.package_id,
                                str(module.path),
                                1,
                                {"import": imported},
                                "explicit/direct",
                                "high",
                                "python-import-package-normalization",
                                [{"file": str(module.path), "line": 1, "symbol": imported}],
                            ))
                    for call_site in code_session.call_sites:
                        import_root = call_site.callee_expression.split(".", 1)[0]
                        package = packages_by_import.get(normalize_package_name(import_root, "PyPI"))
                        if package is None:
                            continue
                        location = call_site.source_range.start
                        import_relationships.append(Relationship(
                            call_site.caller_symbol_id,
                            "IMPORTS_PACKAGE",
                            package.package_id,
                            location.file,
                            location.line,
                            {"call": call_site.callee_expression},
                            "explicit/direct",
                            "high",
                            "resolved-call-package-import",
                            [{"file": location.file, "line": location.line, "symbol": call_site.callee_expression}],
                        ))
                    result.relationships.extend(import_relationships)
                result.models, model_relationships = build_model_inventory(result)
                result.relationships.extend(model_relationships)
                result.relationships = list({
                    (relationship.source_id, relationship.relation, relationship.target_id): relationship
                    for relationship in result.relationships
                }.values())
            except (OSError, ValueError, TypeError, KeyError, RuntimeError) as exc:
                result.errors.append(ScanError("bom-inventory", str(self.root), str(exc)))

            if self.request.allow_network_enrichment and result.packages:
                try:
                    base_provider = self.request.vulnerability_provider or OSVVulnerabilityProvider()
                    cache_path = self.request.vulnerability_cache_path or self.root / ".agentguard" / "cache" / "osv.json"
                    provider = CachedVulnerabilityProvider(
                        base_provider,
                        cache_path,
                        timedelta(seconds=max(0, self.request.vulnerability_cache_ttl_seconds)),
                    )
                    result.vulnerabilities = enrich_packages(result.packages, provider)
                    packages = {package.package_id: package for package in result.packages}
                    for vulnerability in result.vulnerabilities:
                        package = packages[vulnerability.affected_package_id]
                        evidence = package.source_evidence[0] if package.source_evidence else {"detail": package.purl}
                        result.relationships.append(Relationship(
                            package.package_id,
                            "HAS_VULNERABILITY",
                            vulnerability.vulnerability_id,
                            str(evidence.get("file", "")),
                            int(evidence.get("line", 1)),
                            {"provider": vulnerability.source, "affected_version_status": vulnerability.affected_version_status},
                            "explicit/direct",
                            "exact",
                            "provider-affected-version-match",
                            [evidence],
                        ))
                except (*NETWORK_ERRORS, ValueError, RuntimeError) as exc:
                    result.errors.append(ScanError("vulnerability-enrichment", str(self.root), str(exc)))

            for relationship in result.relationships:
                relationship.normalize_paths(self.root)

        findings = []
        if python_paths:
            try:
                analyzer = ProjectPythonAnalyzer.from_files(self.root, python_paths, self.native_rules, code_session)
                findings.extend(analyzer.analyze())
            except (OSError, ValueError, RuntimeError) as exc:
                result.errors.append(ScanError("project-python", str(self.root), str(exc)))

        for path in (item for item in paths if item.suffix.lower() != ".py"):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
                if self.request.enable_tree_sitter and path.suffix.lower() in {".js", ".jsx", ".ts", ".tsx"}:
                    findings.extend(TreeSitterAnalyzer(path, text, self.native_rules).analyze())
                findings.extend(ConfigAnalyzer(path, text, self.native_rules).analyze())
            except (OSError, ValueError, SyntaxError) as exc:
                result.errors.append(ScanError("file-analyzer", str(path), str(exc)))

        if self.request.include_skill_analysis and self.skill_rules:
            try:
                findings.extend(SkillSecurityAnalyzer(
                    self.root,
                    self.skill_rules,
                    allow_network=self.request.allow_network_enrichment,
                    repository_paths=repository_paths,
                    session=code_session,
                ).scan())
            except (OSError, ValueError, SyntaxError, RuntimeError) as exc:
                result.errors.append(ScanError("skill-security", str(self.root), str(exc)))

        # Preserve the v0.2 fingerprint algorithm, then normalize machine paths.
        for finding in findings:
            finding.finalize(self.root)
        findings = list({finding.fingerprint: finding for finding in findings}.values())
        findings = _consolidate_equivalent_flow_findings(findings)
        enrich_findings(findings, self.rules)
        for finding in findings:
            finding.normalize_paths(self.root)
        result.findings = sorted(findings, key=lambda item: (_severity_rank(item.severity), item.rule_id, item.file, item.line), reverse=True)
        try:
            attribute_findings(result)
        except (OSError, ValueError, RuntimeError, TypeError) as exc:
            result.errors.append(ScanError("provenance-attribution", str(self.root), str(exc)))

        result.metrics.duration_ms = int((time.perf_counter() - started) * 1000)
        return result.finish(status="completed_with_errors" if result.errors else "completed")


def scan(request: ScanRequest | Path | str) -> ScanResult:
    if isinstance(request, (str, Path)):
        request = ScanRequest(Path(request))
    return Scanner(request).scan()


def _severity_rank(value: str) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(value.lower(), 0)


def _consolidate_equivalent_flow_findings(findings: list[Finding]) -> list[Finding]:
    """Keep one rich finding when native rules matched the exact same flow."""
    grouped: dict[str, list[Finding]] = {}
    passthrough: list[Finding] = []
    for finding in findings:
        if (
            finding.engine_metadata.get("engine") == "project-python"
            and finding.semantic_anchor
            and any(node.kind == "sink" for node in finding.evidence)
        ):
            grouped.setdefault(finding.semantic_anchor, []).append(finding)
        else:
            passthrough.append(finding)

    for equivalent in grouped.values():
        equivalent.sort(
            key=lambda finding: (
                0 if finding.rule_id.startswith("AIR-") else 1,
                -_severity_rank(finding.severity),
                finding.rule_id,
            )
        )
        primary = equivalent[0]
        if len(equivalent) > 1:
            primary.engine_metadata["related_rules"] = [
                {
                    "rule_id": finding.rule_id,
                    "title": finding.title,
                    "severity": finding.severity,
                }
                for finding in equivalent[1:]
            ]
            primary.engine_metadata["consolidated_equivalent_findings"] = len(equivalent) - 1
        passthrough.append(primary)
    semantic_groups: dict[tuple[str, int, str], list[Finding]] = {}
    final: list[Finding] = []
    for finding in passthrough:
        family = _finding_semantic_family(finding)
        if family:
            semantic_groups.setdefault((finding.file, finding.line, family), []).append(finding)
        else:
            final.append(finding)

    for equivalent in semantic_groups.values():
        native = [finding for finding in equivalent if not finding.rule_id.startswith("NVS-")]
        if not native:
            final.extend(equivalent)
            continue
        native.sort(
            key=lambda finding: (
                0 if finding.engine_metadata.get("engine") == "project-python" else 1,
                -_severity_rank(finding.severity),
                finding.rule_id,
            )
        )
        primary = native[0]
        related = list(primary.engine_metadata.get("related_rules", []))
        for finding in equivalent:
            if finding is primary:
                continue
            related.append(
                {
                    "rule_id": finding.rule_id,
                    "title": finding.title,
                    "severity": finding.severity,
                }
            )
            related.extend(finding.engine_metadata.get("related_rules", []))
        if related:
            primary.engine_metadata["related_rules"] = list(
                {item["rule_id"]: item for item in related}.values()
            )
            primary.engine_metadata["consolidated_equivalent_findings"] = len(
                primary.engine_metadata["related_rules"]
            )
        final.append(primary)
    return final


def _finding_semantic_family(finding: Finding) -> str:
    explicit = {
        "AIR-EXEC-001": "code-execution",
        "AIR-EXEC-007": "remote-script-execution",
        "AIR-NET-004": "tls-verification-disabled",
        "AIR-MODEL-010": "tls-verification-disabled",
        "AIR-SKILL-002": "remote-script-execution",
        "NVS-SC2": "remote-script-execution",
        "NVS-AST1": "code-execution",
        "NVS-AST2": "code-execution",
        "NVS-AST4": "code-execution",
        "NVS-AST5": "code-execution",
        "NVS-TM1": "code-execution",
        "NVS-TT5": "code-execution",
        "NVS-P3": "data-exfiltration",
        "NVS-TT3": "data-exfiltration",
        "NVS-TT4": "data-exfiltration",
    }
    low_code = finding.code.lower()
    if finding.rule_id == "NVS-E1":
        if ("curl " in low_code or "wget " in low_code) and (
            "| bash" in low_code or "| sh" in low_code
        ):
            return "remote-script-execution"
        return "data-exfiltration"
    if finding.rule_id == "NVS-TM3" and "verify" in low_code and "false" in low_code:
        return "tls-verification-disabled"
    if finding.rule_id in explicit:
        return explicit[finding.rule_id]
    if finding.engine_metadata.get("engine") != "project-python":
        return ""
    sinks = {
        label
        for node in finding.evidence
        if node.kind == "sink"
        for label in node.label.split(",")
    }
    if sinks.intersection({"shell_execution", "dynamic_code"}):
        return "code-execution"
    if "network_request" in sinks and any(
        node.kind == "source" and "sensitive_data" in node.label
        for node in finding.evidence
    ):
        return "data-exfiltration"
    return ""
