from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from agentguard_core.rules import RuleStore
from agentguard_core.scanner import bundled_rules_dir

ROOT = Path(__file__).resolve().parents[1]
COVERAGE = ROOT / "RULE_COVERAGE.json"

VALIDATED = {
    "AIR-EXEC-001": {
        "languages": ["python"],
        "frameworks_tested": ["generic Python agent/tool", "OpenAI-compatible model output"],
        "positive_fixtures": [
            "examples/vulnerable_agent/app.py",
            "tests/fixtures/code_intelligence/vulnerable_attribute_container/app.py",
            "tests/fixtures/code_intelligence/vulnerable_cross_file_nested/app.py",
            "tests/fixtures/provenance/vulnerable_cross_file/app.py",
        ],
        "negative_fixtures": [
            "tests/fixtures/code_intelligence/safe_allowlist/app.py",
            "tests/fixtures/code_intelligence/safe_container_entry/app.py",
            "tests/fixtures/code_intelligence/safe_numeric_sanitizer/app.py",
            "tests/fixtures/provenance/safe_cross_file/app.py",
        ],
        "expected_evidence_shape": ["source", "zero_or_more:propagator", "sink"],
        "validation_tests": [
            "tests/test_code_intelligence.py",
            "tests/test_provenance.py::test_cross_file_finding_attribution_and_real_attack_path",
        ],
    },
    "NVS-AR1": {"expected_evidence_shape": ["skill-static"]},
    "NVS-AR3": {"expected_evidence_shape": ["skill-static"]},
    "NVS-P1": {"expected_evidence_shape": ["skill-static"]},
    "NVS-PE3": {"expected_evidence_shape": ["skill-static"]},
    "NVS-AST1": {"expected_evidence_shape": ["ast"]},
    "NVS-AST4": {"expected_evidence_shape": ["ast"]},
    "NVS-LP2": {"expected_evidence_shape": ["permission"]},
}

for rule_id, values in VALIDATED.items():
    if rule_id.startswith("NVS-"):
        values.setdefault("languages", ["markdown", "python"])
        values.setdefault("frameworks_tested", ["AgentGuard skill manifest"])
        values.setdefault(
            "positive_fixtures",
            [
                "examples/vulnerable_skill/SKILL.md",
                "examples/vulnerable_skill/payload.py",
            ],
        )
        values.setdefault(
            "negative_fixtures",
            [
                "tests/fixtures/quality/skill_false_positive/SKILL.md",
                "tests/fixtures/quality/skill_false_positive/helper.py",
            ],
        )
        values.setdefault(
            "validation_tests",
            [
                "tests/test_core.py::test_native_skill_engine_runs_without_external_skillspector",
                "tests/test_milestone4.py::test_validated_skill_rules_resist_false_positive_fixture",
            ],
        )


def analysis_engine(tier: str) -> str:
    return {
        "deep-flow-capable": "agentguard-python-dataflow",
        "structural-config-capable": "agentguard-structural-config",
        "semantic-control-flow-enhancement": "agentguard-catalog-routing",
        "native-static": "agentguard-skill-static",
        "native-behavior-mismatch": "agentguard-skill-behavior",
        "native-network-conditional": "agentguard-skill-network",
    }[tier]


def languages(tier: str) -> list[str]:
    if tier == "deep-flow-capable":
        return ["python"]
    if tier == "structural-config-capable":
        return ["python", "javascript", "typescript", "yaml", "json", "toml", "terraform", "dockerfile"]
    if tier in {"native-static", "native-behavior-mismatch"}:
        return ["markdown", "python", "javascript", "typescript", "shell", "powershell", "yaml", "json", "toml"]
    if tier == "native-network-conditional":
        return ["python-manifest", "javascript-manifest"]
    return []


def evidence_shape(analysis_type: str, tier: str) -> list[str]:
    if tier == "native-network-conditional":
        return ["dependency"]
    if analysis_type == "taint":
        return ["source", "zero_or_more:propagator", "sink"]
    if analysis_type == "config":
        return ["config"]
    if analysis_type == "secret":
        return ["config_or_structural"]
    if analysis_type == "structural":
        return ["structural"]
    if analysis_type == "control_flow":
        return ["control-flow"]
    if analysis_type == "dependency":
        return ["dependency"]
    return ["skill-static"]


def default_status(tier: str) -> tuple[str, str, str]:
    if tier == "semantic-control-flow-enhancement":
        return (
            "requires_dedicated_detector",
            "not_established",
            "Catalog intent is routed but no dedicated semantic/control-flow detector with positive and negative fixtures is proven.",
        )
    if tier == "native-network-conditional":
        return (
            "network_conditional",
            "network_conditional",
            "Requires explicit network access; provider data changes over time and no deterministic live-result fixture is claimed.",
        )
    return (
        "implemented_unvalidated",
        "offline_deterministic",
        "An executable analyzer path exists, but this rule lacks dedicated positive and false-positive-oriented negative regression fixtures.",
    )


def main() -> None:
    document = json.loads(COVERAGE.read_text(encoding="utf-8"))
    catalog = {rule.id: rule for rule in RuleStore(bundled_rules_dir()).load()}
    for record in document["rules"]:
        rule = catalog[record["rule_id"]]
        record["engine"] = rule.engine
        record["analysis_type"] = rule.analysis.type
        tier = record["implementation_tier"]
        status, deterministic, limitation = default_status(tier)
        record.update({
            "implementation_status": status,
            "analysis_engine": analysis_engine(tier),
            "languages": languages(tier),
            "frameworks_tested": [],
            "positive_fixtures": [],
            "negative_fixtures": [],
            "expected_evidence_shape": evidence_shape(record["analysis_type"], tier),
            "known_limitations": limitation,
            "deterministic_status": deterministic,
            "validation_tests": [],
        })
        if record["rule_id"] == "AIR-NET-001":
            record.update({
                "implementation_status": "partially_validated",
                "languages": ["python"],
                "frameworks_tested": ["generic Python agent/tool"],
                "positive_fixtures": ["examples/vulnerable_agent/app.py"],
                "validation_tests": ["tests/test_core.py::test_vulnerable_fixture_has_enriched_findings"],
                "known_limitations": "A positive regression exists, but no rule-specific false-positive-oriented negative fixture is proven.",
            })
        override = VALIDATED.get(record["rule_id"])
        if override:
            record.update(override)
            record["implementation_status"] = "validated"
            record["deterministic_status"] = "offline_deterministic"
            record["known_limitations"] = "Validated for the listed fixtures; unlisted language and framework variants remain unproven."

    counts = Counter(record["implementation_status"] for record in document["rules"])
    output = {key: value for key, value in document.items() if key not in {"rules", "quality_status"}}
    output["quality_status"] = {
        "milestone": 4,
        "status": "validated",
        "schema": "agentguard-rule-quality/1.0",
        "validated_rules": counts["validated"],
        "implementation_statuses": dict(sorted(counts.items())),
        "note": "Validated means both positive and false-positive-oriented negative fixtures plus named regression tests. Empty fixture lists are explicit quality gaps, not implied coverage.",
    }
    output["rules"] = document["rules"]
    COVERAGE.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
