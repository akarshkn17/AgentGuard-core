from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .rules import Rule

QUALITY_SCHEMA = "agentguard-rule-quality/1.0"
REPORT_SCHEMA = "agentguard-rule-quality-report/1.0"
IMPLEMENTATION_STATUSES = {
    "validated",
    "partially_validated",
    "implemented_unvalidated",
    "requires_dedicated_detector",
    "network_conditional",
}
DETERMINISTIC_STATUSES = {"offline_deterministic", "network_conditional", "not_established"}
REQUIRED_RULE_FIELDS = {
    "implementation_status",
    "analysis_engine",
    "languages",
    "frameworks_tested",
    "positive_fixtures",
    "negative_fixtures",
    "expected_evidence_shape",
    "known_limitations",
    "deterministic_status",
    "validation_tests",
}


@dataclass(frozen=True, slots=True)
class QualityValidationIssue:
    code: str
    rule_id: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


class RuleQualityHarness:
    """Validate auditable per-rule quality evidence without executing detectors."""

    def __init__(self, manifest_path: Path, document: dict[str, Any], rules: list[Rule]):
        self.manifest_path = manifest_path.resolve()
        self.root = self.manifest_path.parent
        self.document = document
        self.rules = rules

    @classmethod
    def load(cls, manifest_path: Path, rules: list[Rule]) -> RuleQualityHarness:
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            raise TypeError("quality manifest must be a JSON object")
        return cls(manifest_path, document, rules)

    @property
    def records(self) -> list[dict[str, Any]]:
        records = self.document.get("rules")
        return records if isinstance(records, list) else []

    def _fixture_issues(self, record: dict[str, Any], field: str) -> list[QualityValidationIssue]:
        rule_id = str(record.get("rule_id") or "<missing>")
        values = record.get(field)
        if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
            return [QualityValidationIssue("invalid-field", rule_id, f"{field} must be a list of paths")]
        issues = []
        for value in values:
            path = (self.root / value).resolve()
            try:
                path.relative_to(self.root)
            except ValueError:
                issues.append(QualityValidationIssue("fixture-outside-root", rule_id, f"{field}: {value}"))
                continue
            if not path.exists():
                issues.append(QualityValidationIssue("missing-fixture", rule_id, f"{field}: {value}"))
        return issues

    def _validation_test_issues(self, record: dict[str, Any]) -> list[QualityValidationIssue]:
        rule_id = str(record.get("rule_id") or "<missing>")
        issues = []
        for reference in record.get("validation_tests") or []:
            parts = reference.split("::", 1)
            file_reference = parts[0]
            path = (self.root / file_reference).resolve()
            if not path.exists():
                issues.append(QualityValidationIssue("missing-validation-test", rule_id, reference))
            elif len(parts) == 2 and parts[1] not in path.read_text(encoding="utf-8", errors="ignore"):
                issues.append(QualityValidationIssue("missing-test-anchor", rule_id, reference))
        return issues

    def validate(self) -> list[QualityValidationIssue]:
        issues: list[QualityValidationIssue] = []
        catalog = {rule.id: rule for rule in self.rules}
        if self.document.get("total_rules") != len(self.rules):
            issues.append(QualityValidationIssue("catalog-count", "", "total_rules does not match the bundled catalog"))
        quality = self.document.get("quality_status")
        if not isinstance(quality, dict) or quality.get("schema") != QUALITY_SCHEMA:
            issues.append(QualityValidationIssue("quality-schema", "", f"quality_status.schema must be {QUALITY_SCHEMA}"))

        seen: set[str] = set()
        for record in self.records:
            if not isinstance(record, dict):
                issues.append(QualityValidationIssue("invalid-record", "", "rule quality record must be an object"))
                continue
            rule_id = str(record.get("rule_id") or "")
            if not rule_id:
                issues.append(QualityValidationIssue("missing-rule-id", "", "rule record has no rule_id"))
                continue
            if rule_id in seen:
                issues.append(QualityValidationIssue("duplicate-rule-id", rule_id, "duplicate quality record"))
            seen.add(rule_id)
            rule = catalog.get(rule_id)
            if rule is None:
                issues.append(QualityValidationIssue("unknown-rule", rule_id, "quality record is not in bundled catalog"))
                continue
            missing = sorted(REQUIRED_RULE_FIELDS - record.keys())
            if missing:
                issues.append(QualityValidationIssue("missing-fields", rule_id, ", ".join(missing)))
                continue
            if record.get("engine") != rule.engine or record.get("analysis_type") != rule.analysis.type:
                issues.append(QualityValidationIssue("catalog-metadata", rule_id, "engine or analysis_type differs from catalog"))
            status = record.get("implementation_status")
            if status not in IMPLEMENTATION_STATUSES:
                issues.append(QualityValidationIssue("implementation-status", rule_id, str(status)))
            deterministic = record.get("deterministic_status")
            if deterministic not in DETERMINISTIC_STATUSES:
                issues.append(QualityValidationIssue("deterministic-status", rule_id, str(deterministic)))
            for field in ("languages", "frameworks_tested", "expected_evidence_shape", "validation_tests"):
                value = record.get(field)
                if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                    issues.append(QualityValidationIssue("invalid-field", rule_id, f"{field} must be a list of strings"))
            if not isinstance(record.get("analysis_engine"), str) or not record.get("analysis_engine"):
                issues.append(QualityValidationIssue("analysis-engine", rule_id, "analysis_engine must be non-empty"))
            if not record.get("expected_evidence_shape"):
                issues.append(QualityValidationIssue("evidence-shape", rule_id, "expected_evidence_shape must be non-empty"))
            if not isinstance(record.get("known_limitations"), str) or not record.get("known_limitations"):
                issues.append(QualityValidationIssue("known-limitations", rule_id, "known_limitations must be non-empty"))
            issues.extend(self._fixture_issues(record, "positive_fixtures"))
            issues.extend(self._fixture_issues(record, "negative_fixtures"))
            issues.extend(self._validation_test_issues(record))
            if status == "validated":
                if not record.get("positive_fixtures") or not record.get("negative_fixtures"):
                    issues.append(QualityValidationIssue("unproven-validation", rule_id, "validated requires positive and negative fixtures"))
                if not record.get("validation_tests"):
                    issues.append(QualityValidationIssue("missing-validation-test", rule_id, "validated requires a named regression test"))
            if status == "network_conditional" and deterministic != "network_conditional":
                issues.append(QualityValidationIssue("network-status", rule_id, "network-conditional rule has inconsistent determinism"))

        for rule_id in sorted(catalog.keys() - seen):
            issues.append(QualityValidationIssue("missing-rule", rule_id, "catalog rule has no quality record"))
        if isinstance(quality, dict):
            counts = Counter(str(record.get("implementation_status")) for record in self.records)
            if quality.get("validated_rules") != counts.get("validated", 0):
                issues.append(QualityValidationIssue("quality-summary", "", "validated_rules does not match records"))
            if quality.get("implementation_statuses") != dict(sorted(counts.items())):
                issues.append(QualityValidationIssue("quality-summary", "", "implementation_statuses does not match records"))
        return issues

    def report(self) -> dict[str, Any]:
        status_counts = Counter(str(record.get("implementation_status")) for record in self.records)
        deterministic_counts = Counter(str(record.get("deterministic_status")) for record in self.records)
        validated = status_counts.get("validated", 0)
        total = len(self.records)
        issues = self.validate()
        return {
            "schema": REPORT_SCHEMA,
            "manifest": self.manifest_path.name,
            "total_rules": total,
            "validated_rules": validated,
            "validated_percent": round((validated / total * 100) if total else 0.0, 2),
            "implementation_statuses": dict(sorted(status_counts.items())),
            "deterministic_statuses": dict(sorted(deterministic_counts.items())),
            "validation_issue_count": len(issues),
            "validation_issues": [issue.to_dict() for issue in issues],
            "gaps": [
                {
                    "rule_id": record.get("rule_id"),
                    "implementation_status": record.get("implementation_status"),
                    "known_limitations": record.get("known_limitations"),
                }
                for record in self.records
                if record.get("implementation_status") != "validated"
            ],
        }
