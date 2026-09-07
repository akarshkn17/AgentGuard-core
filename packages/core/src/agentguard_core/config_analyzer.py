from __future__ import annotations

import re
from pathlib import Path

from .models import EvidenceNode, Finding
from .rules import Rule


class ConfigAnalyzer:
    def __init__(self, path: Path, text: str, rules: list[Rule]):
        self.path = path
        self.text = text
        self.rules = rules
        self.rules_by_id = {rule.id: rule for rule in rules}
        self.lines = text.splitlines()

    def analyze(self) -> list[Finding]:
        out: list[Finding] = []
        is_markdown = self.path.suffix.lower() in {".md", ".markdown"} or self.path.name.upper() == "SKILL.MD"
        is_mcp = "mcp" in str(self.path).lower() or "mcp" in self.text[:2000].lower()
        is_skill = self.path.name.upper() == "SKILL.MD" or "skill" in str(self.path).lower()
        is_skill_document = self.path.name.upper() == "SKILL.MD" or ".skill." in self.path.name.lower()
        is_cloud = self.path.suffix.lower() == ".tf" or self.path.name == "Dockerfile" or any(
            item in str(self.path).lower() for item in ("k8s", "kubernetes", "helm", "terraform")
        )
        is_config = self.path.suffix.lower() in {".yaml", ".yml", ".json", ".toml", ".tf"} or self.path.name == "Dockerfile"
        is_executable_instruction = is_skill or self.path.suffix.lower() in {
            ".sh",
            ".bash",
            ".ps1",
        } or self.path.name == "Dockerfile"
        is_rule_catalog = bool(
            re.search(r"(?m)^- id: (?:AIR|CUSTOM-AI)-", self.text)
            and re.search(r"(?m)^\s*engine:\s*agentguard\s*$", self.text)
        )

        def emit(rule_id: str, lineno: int, label: str, line: str) -> None:
            rule = self.rules_by_id.get(rule_id)
            if rule is None:
                return
            node = EvidenceNode("config", label, str(self.path), lineno, "", line.strip())
            out.append(
                Finding(
                    rule.id,
                    rule.name,
                    rule.severity.title(),
                    str(self.path),
                    lineno,
                    rule.message or rule.name,
                    [node],
                    line.strip(),
                    rule.analysis.type,
                ).finalize()
            )

        if not is_markdown and not is_rule_catalog:
            for lineno, line in enumerate(self.lines, 1):
                low = line.lower()
                if is_config and re.search(r"verify\s*[:=]\s*false", line, re.IGNORECASE):
                    emit("AIR-NET-004", lineno, "TLS verification disabled", line)
                    if any(term in low for term in ("model", "provider", "openai", "anthropic", "llm", "client")):
                        emit("AIR-MODEL-010", lineno, "Provider TLS verification disabled", line)
                if is_config and re.search(r"trust_remote_code\s*[:=]\s*true", line, re.IGNORECASE):
                    emit("AIR-MODEL-001", lineno, "Remote model code enabled", line)
                if is_config and re.search(r"debug\s*[:=]\s*true", line, re.IGNORECASE):
                    emit("AIR-SECRET-005", lineno, "Debug mode enabled", line)
                if is_config and re.search(r"privileged\s*:\s*true", line, re.IGNORECASE):
                    emit("AIR-CLOUD-002", lineno, "Privileged container", line)
                if is_config and re.search(r"hostPath\s*:|/var/run/docker\.sock", line, re.IGNORECASE):
                    emit("AIR-CLOUD-002", lineno, "Host/container escape capability", line)
                if is_config and is_mcp and re.search(
                    r"access-control-allow-origin\s*[:=]\s*[\"']?\*", line, re.IGNORECASE
                ):
                    emit("AIR-MCP-004", lineno, "Wildcard CORS", line)
                if is_config and re.search(
                    r"https?://169\.254\.169\.254|metadata\.google\.internal", line, re.IGNORECASE
                ):
                    emit("AIR-NET-006", lineno, "Cloud metadata endpoint", line)
                mutable = is_config and re.search(
                    r"\b(main|master|latest|HEAD)\b", line, re.IGNORECASE
                )
                model_version_context = re.search(
                    r"\b(model(?:_id|_name|_version)?|revision|model_revision)\b\s*[:=]",
                    line,
                    re.IGNORECASE,
                )
                if mutable and model_version_context:
                    emit("AIR-MODEL-004", lineno, "Mutable model version/ref", line)
                if mutable and re.search(r"\b(lora|adapter)\b", line, re.IGNORECASE):
                    emit("AIR-MODEL-005", lineno, "Mutable adapter source", line)
                if mutable and is_skill and any(term in low for term in ("source", "url", "repo", "ref", "tag")):
                    emit("AIR-SKILL-004", lineno, "Mutable skill source/ref", line)
                if mutable and is_skill and re.search(r"\b(pip|npm|npx|uv|poetry)\b", low):
                    emit("AIR-EXEC-008", lineno, "Unpinned runtime package execution", line)
                secret_match = re.search(
                    r"(api[_-]?key|token|secret|password)\s*[:=]\s*[\"']([^\"']{8,})[\"']",
                    line,
                    re.IGNORECASE,
                )
                placeholder = secret_match and re.search(
                    r"(?:^|[-_])(test|fake|example|dummy|placeholder|redacted)(?:[-_]|$)",
                    secret_match.group(2),
                    re.IGNORECASE,
                )
                if secret_match and not placeholder:
                    emit("AIR-SECRET-001", lineno, "Potential hard-coded secret", line)
                    if "mcp" in str(self.path).lower() or "mcp" in low:
                        emit("AIR-MCP-003", lineno, "Static MCP credential", line)
                        emit("AIR-MCP-015", lineno, "Secret in MCP configuration", line)
                    if is_cloud:
                        emit("AIR-CLOUD-001", lineno, "Static cloud credential", line)
                if is_executable_instruction and ("curl " in low or "wget " in low) and (
                    "| bash" in low or "| sh" in low
                ):
                    emit("AIR-EXEC-007", lineno, "Downloaded content executed", line)
                    if is_skill:
                        emit(
                            "AIR-SKILL-002",
                            lineno,
                            "Skill downloads and executes remote script",
                            line,
                        )
        if is_markdown and is_skill_document:
            for lineno, line in enumerate(self.lines, 1):
                low = line.lower()
                if ("curl " in low or "wget " in low) and ("| bash" in low or "| sh" in low):
                    emit("AIR-EXEC-007", lineno, "Downloaded content executed", line)
                    if is_skill:
                        emit("AIR-SKILL-002", lineno, "Skill downloads and executes remote script", line)
                if is_skill and re.search(
                    r"(?i)(tools|permissions|capabilities)\s*[:=]\s*\*", line
                ):
                    emit("AIR-SKILL-008", lineno, "Wildcard capability", line)
        return list({finding.fingerprint: finding for finding in out}.values())
