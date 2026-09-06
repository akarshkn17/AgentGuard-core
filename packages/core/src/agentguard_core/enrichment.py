from __future__ import annotations

from .models import Finding
from .rules import Rule


def enrich_findings(findings: list[Finding], rules: list[Rule]) -> list[Finding]:
    """Attach rule-authored explanation/remediation without altering detection."""
    by_id = {rule.id: rule for rule in rules}
    for finding in findings:
        rule = by_id.get(finding.rule_id)
        if not rule:
            continue
        finding.title = finding.title or rule.name
        finding.description = rule.description or _description(rule)
        finding.category = rule.category
        finding.remediation = list(rule.remediation)
        finding.source_description = rule.source_description
        finding.sink_description = rule.sink_description
        finding.detection_logic = rule.detection_logic
        finding.references = list(rule.references)
        finding.mappings = dict(rule.mappings)
        finding.cwe = list(rule.cwe)
        finding.rule_version = rule.rule_version
        finding.engine_metadata.setdefault("rule_engine", rule.engine)
    return findings


def _description(rule: Rule) -> str:
    parts = [rule.message or rule.name]
    if rule.source_description and rule.sink_description:
        parts.append(f"Risk path: {rule.source_description} can reach {rule.sink_description}.")
    elif rule.detection_logic:
        parts.append(rule.detection_logic)
    return " ".join(part.strip().rstrip(".") + "." for part in parts if part.strip())
