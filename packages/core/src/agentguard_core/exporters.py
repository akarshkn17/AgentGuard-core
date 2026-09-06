from __future__ import annotations

import csv
import json
from io import StringIO
from typing import Any
from xml.etree.ElementTree import Element, SubElement, tostring

from .contracts import ENGINE_VERSION, ScanResult


def result_json(result: ScanResult, *, pretty: bool = True) -> str:
    return json.dumps(result.to_dict(), indent=2 if pretty else None, ensure_ascii=False)


def findings_json(result: ScanResult, *, pretty: bool = True) -> str:
    return json.dumps([item.to_dict() for item in result.findings], indent=2 if pretty else None, ensure_ascii=False)


def sarif(result: ScanResult) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for finding in result.findings:
        rules.setdefault(finding.rule_id, {
            "id": finding.rule_id,
            "name": finding.title or finding.name,
            "shortDescription": {"text": finding.title or finding.name},
            "fullDescription": {"text": finding.description or finding.message},
            "help": {"text": "Remediation: " + "; ".join(finding.remediation)},
            "properties": {"category": finding.category, "severity": finding.severity, "cwe": finding.cwe},
        })
        result_item: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": _sarif_level(finding.severity),
            "message": {"text": finding.message},
            "partialFingerprints": {"agentguardFindingId": finding.finding_id, "agentguardFingerprint": finding.fingerprint},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": finding.file},
                "region": {"startLine": max(1, finding.line)},
            }}],
            "properties": {
                "severity": finding.severity,
                "analysisType": finding.analysis_type,
                "category": finding.category,
                "remediation": finding.remediation,
            },
        }
        if finding.code:
            result_item["locations"][0]["physicalLocation"]["region"]["snippet"] = {"text": finding.code}
        results.append(result_item)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "AgentGuard Core", "version": ENGINE_VERSION, "rules": list(rules.values())}},
            "results": results,
        }],
    }


def csv_findings(result: ScanResult) -> str:
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "finding_id", "fingerprint", "severity", "rule_id", "title", "category", "analysis_type",
        "file", "line", "description", "remediation", "source_description", "sink_description", "cwe"
    ])
    writer.writeheader()
    for f in result.findings:
        writer.writerow({
            "finding_id": f.finding_id, "fingerprint": f.fingerprint, "severity": f.severity,
            "rule_id": f.rule_id, "title": f.title or f.name, "category": f.category,
            "analysis_type": f.analysis_type, "file": f.file, "line": f.line,
            "description": f.description, "remediation": " | ".join(f.remediation),
            "source_description": f.source_description, "sink_description": f.sink_description,
            "cwe": " | ".join(f.cwe),
        })
    return output.getvalue()


def markdown_summary(result: ScanResult) -> str:
    lines = ["# AgentGuard Scan Summary", "", f"- Scan: `{result.scan.scan_id}`", f"- Findings: **{len(result.findings)}**", f"- AI assets: **{len(result.inventory)}**", f"- Files scanned: **{result.metrics.files_scanned}**", "", "## Findings", "", "| Severity | Rule | Finding | Location |", "|---|---|---|---|"]
    for f in result.findings:
        lines.append(f"| {f.severity} | `{f.rule_id}` | {f.title or f.name} | `{f.file}:{f.line}` |")
    return "\n".join(lines) + "\n"


def junit_xml(result: ScanResult) -> str:
    suite = Element("testsuite", {
        "name": "AgentGuard", "tests": str(max(1, len(result.findings))),
        "failures": str(len(result.findings)), "errors": str(len(result.errors)),
        "time": f"{result.metrics.duration_ms / 1000:.3f}",
    })
    if not result.findings:
        SubElement(suite, "testcase", {"classname": "agentguard.scan", "name": "no-findings"})
    for finding in result.findings:
        case = SubElement(suite, "testcase", {"classname": f"agentguard.{finding.category or 'security'}", "name": f"{finding.rule_id}:{finding.finding_id}"})
        failure = SubElement(case, "failure", {"type": finding.severity.lower(), "message": finding.message})
        failure.text = f"{finding.description}\nLocation: {finding.file}:{finding.line}\nRemediation: {'; '.join(finding.remediation)}"
    return tostring(suite, encoding="unicode", xml_declaration=True)


def _sarif_level(severity: str) -> str:
    return {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}.get(severity.lower(), "warning")
