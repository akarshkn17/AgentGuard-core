from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from agentguard_core import ENGINE_VERSION, ScanRequest, generate_agent_bom, generate_cyclonedx, generate_provenance_graph, scan as core_scan
from agentguard_core.exporters import csv_findings, findings_json, junit_xml, markdown_summary, result_json, sarif
from agentguard_core.reporting import detailed_html, summary_html
from agentguard_core.rules import RuleStore
from agentguard_core.scanner import bundled_rules_dir

app = typer.Typer(help="AgentGuard CLI — local/CI adapter for AgentGuard Core", no_args_is_help=True)
rules_app = typer.Typer(help="Rule catalog commands")
app.add_typer(rules_app, name="rules")
console = Console()

FORMATS = {"json", "findings-json", "sarif", "csv", "junit", "html", "html-summary", "markdown", "aibom", "agent-bom", "graph"}
DEFAULT_EXPORTS = ["json", "sarif", "html", "html-summary"]
SEVERITY = {"none": 99, "critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="Repository/directory to scan")] = Path("."),
    output_dir: Annotated[Path, typer.Option("--output-dir", "-o", help="Directory for exported reports")] = Path("agentguard-results"),
    format: Annotated[list[str] | None, typer.Option("--format", "-f", help="Repeatable: json,sarif,csv,junit,html,html-summary,markdown,aibom,agent-bom,graph")] = None,
    rules: Annotated[Path | None, typer.Option("--rules", help="Custom rule directory; defaults to bundled AgentGuard rules")] = None,
    rule: Annotated[list[str] | None, typer.Option("--rule", help="Run only selected rule ID; repeatable")] = None,
    fail_on: Annotated[str, typer.Option("--fail-on", help="CI gate: none|critical|high|medium|low|info")] = "none",
    no_inventory: Annotated[bool, typer.Option("--no-inventory", help="Skip AI/Agent inventory discovery")] = False,
    no_tree_sitter: Annotated[bool, typer.Option("--no-tree-sitter", help="Disable optional JS/TS tree-sitter analyzer")] = False,
    no_skill_analysis: Annotated[bool, typer.Option("--no-skill-analysis", help="Disable native skill-security analysis")] = False,
    network_enrichment: Annotated[bool, typer.Option("--network-enrichment", help="Enable OSV/package-maintenance lookups for supply-chain rules")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Print descriptions, remediation and evidence")] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Suppress table output; useful in CI")] = False,
):
    """Scan a repository using the local AgentGuard Core. No authentication is used."""
    if fail_on.lower() not in SEVERITY:
        raise typer.BadParameter("--fail-on must be one of none,critical,high,medium,low,info")
    requested_formats = format or DEFAULT_EXPORTS
    unknown = [item for item in requested_formats if item not in FORMATS]
    if unknown:
        raise typer.BadParameter(f"Unknown format(s): {', '.join(unknown)}")

    result = core_scan(ScanRequest(
        root=path,
        rules_dir=rules,
        include_inventory=not no_inventory,
        enable_tree_sitter=not no_tree_sitter,
        rule_ids=set(rule or []),
        include_skill_analysis=not no_skill_analysis,
        allow_network_enrichment=network_enrichment,
    ))

    if not quiet:
        _print_result(result, verbose=verbose)

    output_dir.mkdir(parents=True, exist_ok=True)
    written = _write_formats(result, output_dir, requested_formats)
    if not quiet:
        console.print("\n[bold]Artifacts[/bold]")
        for item in written:
            console.print(f"  {item}")

    threshold = SEVERITY[fail_on.lower()]
    if threshold < 99 and any(SEVERITY.get(f.severity.lower(), 0) >= threshold for f in result.findings):
        if not quiet:
            console.print(f"[red]Policy gate failed:[/red] finding at or above {fail_on.lower()} severity")
        raise typer.Exit(1)
    if result.errors:
        # Analysis errors are visible in the canonical result; don't silently pass infrastructure failures.
        if not quiet:
            console.print(f"[yellow]Scan completed with {len(result.errors)} analyzer error(s).[/yellow]")


@app.command()
def inventory(
    path: Annotated[Path, typer.Argument()] = Path("."),
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
):
    """Discover AI/agent assets with normalized categories and version provenance."""
    result = core_scan(ScanRequest(path, include_inventory=True, rule_ids={"__inventory_only__"}))
    table = Table(title=f"AgentGuard AI Inventory · {len(result.inventory)} assets")
    for column in ("Type", "Category", "Name", "Framework", "Version", "Version Source", "Location"):
        table.add_column(column)
    for entity in result.inventory:
        table.add_row(entity.entity_type, entity.category, entity.name, entity.framework, entity.version, entity.version_source, f"{entity.file}:{entity.line}")
    console.print(table)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps([item.to_dict() for item in result.inventory], indent=2), encoding="utf-8")
        console.print(output)


@app.command()
def bom(
    path: Annotated[Path, typer.Argument()] = Path("."),
    kind: Annotated[str, typer.Option("--kind", help="aibom|agent-bom")] = "aibom",
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
):
    """Generate an AI BOM (CycloneDX 1.7) or AgentGuard Agent BOM."""
    result = core_scan(ScanRequest(path, include_inventory=True, rule_ids={"__inventory_only__"}))
    if kind == "aibom":
        data = generate_cyclonedx(result)
        output = output or Path("agentguard-aibom.cdx.json")
    elif kind == "agent-bom":
        data = generate_agent_bom(result)
        output = output or Path("agentguard-agent-bom.json")
    else:
        raise typer.BadParameter("--kind must be aibom or agent-bom")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, indent=2), encoding="utf-8")
    console.print(output)


@app.command()
def graph(
    path: Annotated[Path, typer.Argument()] = Path("."),
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("agentguard-provenance.json"),
):
    """Generate the UI/architecture provenance graph JSON contract."""
    result = core_scan(ScanRequest(path, include_inventory=True))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(generate_provenance_graph(result), indent=2), encoding="utf-8")
    console.print(output)


@app.command()
def version():
    console.print(f"AgentGuard CLI 0.4.0 · Core {ENGINE_VERSION}")


@rules_app.command("list")
def rules_list(rules: Annotated[Path | None, typer.Option("--rules")] = None):
    items = RuleStore(rules or bundled_rules_dir()).load()
    table = Table(title=f"AgentGuard rules · {len(items)}")
    for column in ("ID", "Severity", "Category", "Analysis", "Name"):
        table.add_column(column)
    for item in items:
        table.add_row(item.id, item.severity, item.category, item.analysis.type, item.name)
    console.print(table)


@rules_app.command("validate")
def rules_validate(rules: Annotated[Path | None, typer.Option("--rules")] = None):
    store = RuleStore(rules or bundled_rules_dir())
    errors = store.validate()
    if errors:
        for rule_id, error in errors:
            console.print(f"[red]{rule_id}: {error}[/red]")
        raise typer.Exit(2)
    console.print(f"[green]Valid: {len(store.rules)} rules[/green]")


def _print_result(result, *, verbose: bool) -> None:
    table = Table(title=f"AgentGuard {result.scan.scan_id[:8]} · {len(result.findings)} findings · {len(result.inventory)} AI assets")
    for column in ("Severity", "Rule", "Finding", "Analysis", "Location"):
        table.add_column(column)
    for f in result.findings:
        table.add_row(f.severity, f.rule_id, f.title or f.name, f.analysis_type, f"{f.file}:{f.line}")
    console.print(table)
    if verbose:
        for f in result.findings:
            console.rule(f"{f.rule_id} · {f.finding_id}")
            console.print(f"[bold]{f.title or f.name}[/bold] ({f.severity})")
            console.print(f.description or f.message)
            if f.remediation:
                console.print("[bold]Remediation[/bold]")
                for step in f.remediation:
                    console.print(f"  • {step}")
            if f.evidence:
                console.print("[bold]Evidence[/bold]")
                for node in f.evidence:
                    console.print(f"  {node.kind}: {node.label} — {node.file}:{node.line}")
    if result.errors:
        console.print(f"[yellow]Analyzer errors: {len(result.errors)}[/yellow]")


def _write_formats(result, output_dir: Path, formats: list[str]) -> list[Path]:
    written: list[Path] = []
    for name in dict.fromkeys(formats):
        if name == "json":
            path, content = output_dir / "agentguard-result.json", result_json(result)
        elif name == "findings-json":
            path, content = output_dir / "agentguard-findings.json", findings_json(result)
        elif name == "sarif":
            path, content = output_dir / "agentguard.sarif", json.dumps(sarif(result), indent=2)
        elif name == "csv":
            path, content = output_dir / "agentguard-findings.csv", csv_findings(result)
        elif name == "junit":
            path, content = output_dir / "agentguard-junit.xml", junit_xml(result)
        elif name == "html":
            path, content = output_dir / "agentguard-report.html", detailed_html(result)
        elif name == "html-summary":
            path, content = output_dir / "agentguard-summary.html", summary_html(result)
        elif name == "markdown":
            path, content = output_dir / "agentguard-summary.md", markdown_summary(result)
        elif name == "aibom":
            path, content = output_dir / "agentguard-aibom.cdx.json", json.dumps(generate_cyclonedx(result), indent=2)
        elif name == "agent-bom":
            path, content = output_dir / "agentguard-agent-bom.json", json.dumps(generate_agent_bom(result), indent=2)
        elif name == "graph":
            path, content = output_dir / "agentguard-provenance.json", json.dumps(generate_provenance_graph(result), indent=2)
        else:
            continue
        path.write_text(content, encoding="utf-8")
        written.append(path)
    return written
