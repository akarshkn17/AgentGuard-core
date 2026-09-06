from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .config_analyzer import ConfigAnalyzer
from .code_intelligence import CodeIntelligenceSession
from .contracts import ScanError, ScanMetadata, ScanMetrics, ScanRequest, ScanResult
from .enrichment import enrich_findings
from .inventory import InventoryDiscoverer
from .project_analyzer import ProjectPythonAnalyzer
from .rules import RuleStore
from .skill_analyzer import SkillSecurityAnalyzer
from .treesitter_analyzer import TreeSitterAnalyzer

DEFAULT_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".yaml", ".yml", ".json", ".toml", ".md", ".tf"}
IGNORED_DIRECTORIES = {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__", ".agentguard"}


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

    def files(self) -> list[Path]:
        return [
            path for path in self.root.rglob("*")
            if path.is_file()
            and not any(part in IGNORED_DIRECTORIES for part in path.parts)
            and (path.suffix.lower() in DEFAULT_EXTENSIONS or path.name in {"Dockerfile", "SKILL.md"})
        ]

    def scan(self) -> ScanResult:
        started = time.perf_counter()
        now = datetime.now(timezone.utc).isoformat()
        metadata = ScanMetadata(str(uuid.uuid4()), str(self.root), now)
        result = ScanResult(metadata, metrics=ScanMetrics())
        paths = self.files()
        result.metrics.files_scanned = len(paths)

        python_paths = [path for path in paths if path.suffix.lower() == ".py"]
        code_session = None
        if python_paths:
            try:
                code_session = CodeIntelligenceSession.from_files(self.root, python_paths)
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
                result.inventory, result.relationships = inventory_discoverer.discover()
            except (OSError, ValueError, SyntaxError, RuntimeError) as exc:
                result.errors.append(ScanError("inventory", str(self.root), str(exc)))

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
                findings.extend(SkillSecurityAnalyzer(self.root, self.skill_rules, allow_network=self.request.allow_network_enrichment).scan())
            except (OSError, ValueError, SyntaxError, RuntimeError) as exc:
                result.errors.append(ScanError("skill-security", str(self.root), str(exc)))

        # Preserve the v0.2 fingerprint algorithm, then normalize machine paths.
        for finding in findings:
            finding.finalize(self.root)
        findings = list({finding.fingerprint: finding for finding in findings}.values())
        enrich_findings(findings, self.rules)
        for finding in findings:
            finding.normalize_paths(self.root)
        result.findings = sorted(findings, key=lambda item: (_severity_rank(item.severity), item.rule_id, item.file, item.line), reverse=True)

        result.metrics.duration_ms = int((time.perf_counter() - started) * 1000)
        return result.finish(status="completed_with_errors" if result.errors else "completed")


def scan(request: ScanRequest | Path | str) -> ScanResult:
    if isinstance(request, (str, Path)):
        request = ScanRequest(Path(request))
    return Scanner(request).scan()


def _severity_rank(value: str) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(value.lower(), 0)
