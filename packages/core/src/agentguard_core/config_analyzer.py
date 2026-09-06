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
        self.lines = text.splitlines()

    def _target_applicable(self, rule: Rule) -> bool:
        targets = set(rule.targets or [])
        low = str(self.path).lower()
        is_skill = self.path.name.upper() == "SKILL.MD" or "skill" in low
        is_mcp = "mcp" in low
        is_cloud = self.path.suffix.lower() == ".tf" or self.path.name == "Dockerfile" or any(
            item in low for item in ("k8s", "kubernetes", "helm", "terraform")
        )
        if is_skill and targets and not targets.intersection({"skill", "plugin", "skill_manifest", "tool"}):
            return False
        if is_mcp and targets and all(target.startswith("mcp") for target in targets):
            return True
        if is_cloud and targets and targets.intersection({"agent_runtime", "cloud_config", "deployment"}):
            return True
        return True

    def analyze(self) -> list[Finding]:
        out: list[Finding] = []
        patterns = [
            (r"(?i)verify\s*[:=]\s*false", "TLS verification disabled", ["tls", "verify=false"]),
            (r"(?i)trust_remote_code\s*[:=]\s*true", "Remote model code enabled", ["remote code", "trust_remote_code"]),
            (r"(?i)debug\s*[:=]\s*true", "Debug mode enabled", ["debug"]),
            (r"(?i)privileged\s*:\s*true", "Privileged container", ["privileged"]),
            (r"(?i)hostPath\s*:|/var/run/docker\.sock", "Host/container escape capability", ["host", "docker.sock", "privileged"]),
            (r"(?i)access-control-allow-origin\s*[:=]\s*[\"']?\*", "Wildcard CORS", ["cors", "origin"]),
            (r"(?i)https?://169\.254\.169\.254|metadata\.google\.internal", "Cloud metadata endpoint", ["metadata", "ssrf"]),
            (r"(?i)\b(main|master|latest|HEAD)\b", "Mutable version/ref", ["unpinned", "floating", "mutable"]),
            (r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*[\"'][^\"']{8,}[\"']", "Potential hard-coded secret", ["hardcoded", "secret", "credential"]),
        ]
        for lineno, line in enumerate(self.lines, 1):
            for pattern, label, hints in patterns:
                if re.search(pattern, line):
                    for rule in self.rules:
                        if not self._target_applicable(rule):
                            continue
                        blob = (
                            rule.name + " " + rule.detection_logic + " " + rule.source_description + " " + rule.sink_description
                        ).lower()
                        if any(hint in blob for hint in hints):
                            node = EvidenceNode("config", label, str(self.path), lineno, "", line.strip())
                            out.append(
                                Finding(
                                    rule.id, rule.name, rule.severity.title(), str(self.path), lineno,
                                    rule.message or rule.name, [node], line.strip(), rule.analysis.type,
                                ).finalize()
                            )
        if self.path.suffix.lower() in (".md", ".markdown") or self.path.name.upper() == "SKILL.MD":
            for lineno, line in enumerate(self.lines, 1):
                low = line.lower()
                if ("curl " in low or "wget " in low) and ("| bash" in low or "| sh" in low):
                    for rule in self.rules:
                        if not self._target_applicable(rule):
                            continue
                        if "downloads and executes remote script" in rule.name.lower() or "downloaded content executed" in rule.name.lower():
                            out.append(
                                Finding(
                                    rule.id, rule.name, rule.severity.title(), str(self.path), lineno,
                                    rule.message or rule.name,
                                    [
                                        EvidenceNode("source", "remote URL", str(self.path), lineno),
                                        EvidenceNode("sink", "shell execution", str(self.path), lineno, detail=line.strip()),
                                    ],
                                    line.strip(), rule.analysis.type,
                                ).finalize()
                            )
                if re.search(r"(?i)(tools|permissions|capabilities)\s*[:=]\s*\*", line):
                    for rule in self.rules:
                        if not self._target_applicable(rule):
                            continue
                        if "wildcard" in rule.name.lower() or "excessive" in rule.name.lower():
                            out.append(
                                Finding(
                                    rule.id, rule.name, rule.severity.title(), str(self.path), lineno,
                                    rule.message or rule.name,
                                    [EvidenceNode("config", "wildcard capability", str(self.path), lineno, detail=line.strip())],
                                    line.strip(), rule.analysis.type,
                                ).finalize()
                            )
        return list({finding.fingerprint: finding for finding in out}.values())
