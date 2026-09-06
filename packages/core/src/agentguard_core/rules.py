from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class AnalysisConfig(BaseModel):
    type: str = "taint"
    interprocedural: bool = True


class Rule(BaseModel):
    id: str
    name: str
    engine: str = "agentguard"
    origin: str = "AgentGuard"
    origin_rule_id: str = ""
    legacy_engine: str = ""
    source_file: str = ""
    implementation: str = "native"
    category: str = "ai-security"
    severity: str = "high"
    targets: list[str] = Field(default_factory=list)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    sources: list[str] = Field(default_factory=list)
    sinks: list[str] = Field(default_factory=list)
    barriers: list[str] = Field(default_factory=list)
    match: dict[str, Any] = Field(default_factory=dict)
    message: str = ""
    description: str = ""
    remediation: list[str] = Field(default_factory=list)
    source_description: str = ""
    sink_description: str = ""
    detection_logic: str = ""
    references: list[str] = Field(default_factory=list)
    mappings: dict[str, list[str]] = Field(default_factory=dict)
    cwe: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    rule_version: str = "1"


class RuleStore:
    def __init__(self, root: Path):
        self.root = root
        self.rules: list[Rule] = []

    def load(self) -> list[Rule]:
        self.rules = []
        if not self.root.exists():
            return []
        for path in sorted(self.root.rglob("*.yaml")):
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            items = data if isinstance(data, list) else [data]
            for item in items:
                if item:
                    self.rules.append(Rule.model_validate(item))
        return self.rules

    def validate(self) -> list[tuple[str, str]]:
        errors: list[tuple[str, str]] = []
        try:
            self.load()
        except Exception as exc:
            errors.append((str(self.root), str(exc)))
            return errors
        ids: set[str] = set()
        for rule in self.rules:
            if rule.id in ids:
                errors.append((rule.id, "duplicate rule id"))
            ids.add(rule.id)
            if not rule.message:
                errors.append((rule.id, "missing message"))
            if not rule.remediation:
                errors.append((rule.id, "missing remediation"))
        return errors
