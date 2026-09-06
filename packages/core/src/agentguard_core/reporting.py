from __future__ import annotations

import html
from collections import Counter
from typing import Any

from .contracts import ScanResult


def _e(value: Any) -> str:
    return html.escape(str(value or ""))


def detailed_html(result: ScanResult) -> str:
    severity = Counter(f.severity.lower() for f in result.findings)
    cards = []
    for f in result.findings:
        evidence = "".join(
            f'<li><b>{_e(node.kind)}</b> — {_e(node.label)} <small>{_e(node.file)}:{node.line}</small><pre>{_e(node.detail)}</pre></li>'
            for node in f.evidence
        ) or "<li>No evidence path was emitted by this rule.</li>"
        remediation = "".join(f"<li>{_e(step)}</li>" for step in f.remediation) or "<li>Review the unsafe flow and apply least privilege/input validation.</li>"
        mappings = " ".join(
            f'<span class="tag">{_e(framework)}: {_e(", ".join(values))}</span>'
            for framework, values in f.mappings.items()
        )
        cards.append(f"""
        <article class="finding">
          <div class="finding-head"><span class="severity {f.severity.lower()}">{_e(f.severity)}</span>
          <div><h3>{_e(f.rule_id)} · {_e(f.title or f.name)}</h3><small>{_e(f.finding_id)} · {_e(f.file)}:{f.line}</small></div></div>
          <p>{_e(f.description or f.message)}</p>
          <div class="grid2"><div><h4>Why this was detected</h4><p>{_e(f.detection_logic or f.message)}</p>
          <p><b>Source:</b> {_e(f.source_description or "N/A")}</p><p><b>Sink:</b> {_e(f.sink_description or "N/A")}</p></div>
          <div><h4>Remediation</h4><ol>{remediation}</ol></div></div>
          {f'<div class="tags">{mappings}</div>' if mappings else ''}
          <details><summary>Evidence path ({len(f.evidence)} steps)</summary><ol class="evidence">{evidence}</ol></details>
          {f'<details><summary>Code</summary><pre>{_e(f.code)}</pre></details>' if f.code else ''}
        </article>""")

    inventory_rows = "".join(
        f"<tr><td>{_e(x.entity_type)}</td><td>{_e(x.category)}</td><td>{_e(x.name)}</td><td>{_e(x.framework)}</td><td>{_e(x.version)}</td><td>{_e(x.version_source)}</td><td>{_e(x.file)}:{x.line}</td></tr>"
        for x in result.inventory
    )
    errors = "".join(f"<li>{_e(err.stage)} · {_e(err.path)} · {_e(err.message)}</li>" for err in result.errors)
    return _page(
        "AgentGuard Detailed Security Report",
        f"""
        <header><h1>AgentGuard Detailed Security Report</h1><p>Scan {_e(result.scan.scan_id)} · {_e(result.scan.status)}</p>
        <p class="muted">{_e(result.scan.root)} · Git {_e(result.scan.git_commit[:12])}</p></header>
        <main>
        <section><h2>Scan summary</h2><div class="metrics">
        {_metric("Findings", len(result.findings))}{_metric("Critical", severity['critical'])}{_metric("High", severity['high'])}
        {_metric("AI assets", len(result.inventory))}{_metric("Files", result.metrics.files_scanned)}{_metric("Duration ms", result.metrics.duration_ms)}
        </div></section>
        <section><h2>Security findings</h2>{''.join(cards) or '<div class="empty">No findings.</div>'}</section>
        <section><h2>AI / Agent inventory</h2><p>Version is reported with provenance so consumers can distinguish package-declared versions from content-hash identities.</p>
        <div class="scroll"><table><thead><tr><th>Type</th><th>Category</th><th>Name</th><th>Framework</th><th>Version</th><th>Version source</th><th>Location</th></tr></thead><tbody>{inventory_rows}</tbody></table></div></section>
        <section><h2>Relationships</h2><p>{len(result.relationships)} statically discovered relationships. Export the full UI-oriented provenance graph with `agentguard scan --format graph` or `agentguard graph`.</p></section>
        {f'<section><h2>Scan errors</h2><ul>{errors}</ul></section>' if errors else ''}
        <section><h2>Methodology</h2><p>AgentGuard performs deterministic static analysis using project-wide Python AST/data-flow analysis, optional JavaScript/TypeScript tree-sitter structural analysis, configuration analysis, and AI asset discovery. A finding represents statically observed code/configuration evidence, not runtime behavior.</p></section>
        </main>""",
    )


def summary_html(result: ScanResult) -> str:
    severity = Counter(f.severity.lower() for f in result.findings)
    categories = Counter(f.category or "uncategorized" for f in result.findings)
    asset_types = Counter(x.entity_type for x in result.inventory)
    top = "".join(
        f"<tr><td><span class='severity {f.severity.lower()}'>{_e(f.severity)}</span></td><td>{_e(f.rule_id)}</td><td>{_e(f.title or f.name)}</td><td>{_e(f.file)}:{f.line}</td></tr>"
        for f in result.findings[:15]
    )
    category_rows = "".join(f"<tr><td>{_e(k)}</td><td>{v}</td></tr>" for k, v in categories.most_common())
    asset_rows = "".join(f"<tr><td>{_e(k)}</td><td>{v}</td></tr>" for k, v in asset_types.most_common())
    return _page(
        "AgentGuard Executive Summary",
        f"""
        <header><h1>AgentGuard Scan Summary</h1><p>{_e(result.scan.status)} · {_e(result.scan.completed_at)}</p><p class="muted">{_e(result.scan.root)}</p></header>
        <main><section><div class="metrics">{_metric('Findings', len(result.findings))}{_metric('Critical', severity['critical'])}{_metric('High', severity['high'])}{_metric('Medium', severity['medium'])}{_metric('AI assets', len(result.inventory))}{_metric('Files', result.metrics.files_scanned)}</div></section>
        <section><h2>Highest priority findings</h2><table><thead><tr><th>Severity</th><th>Rule</th><th>Finding</th><th>Location</th></tr></thead><tbody>{top}</tbody></table></section>
        <section class="grid2"><div><h2>Finding categories</h2><table>{category_rows}</table></div><div><h2>Inventory composition</h2><table>{asset_rows}</table></div></section>
        <section><h2>Decision guidance</h2><p>Use the detailed report for evidence and remediation. CI policy should fail on an agreed severity threshold rather than on the raw finding count.</p></section></main>""",
    )


def _metric(label: str, value: Any) -> str:
    return f'<div class="metric"><span>{_e(label)}</span><strong>{_e(value)}</strong></div>'


def _page(title: str, body: str) -> str:
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(title)}</title><style>
:root{{--ink:#172033;--muted:#667085;--line:#d9e0ea;--panel:#f6f8fb;--accent:#2457d6;--critical:#b42318;--high:#b54708;--medium:#b25e09;--low:#156fee}}
*{{box-sizing:border-box}}body{{margin:0;font:14px/1.55 Inter,Segoe UI,Arial,sans-serif;color:var(--ink);background:#fff}}header,main{{max-width:1240px;margin:auto;padding:26px 34px}}header{{border-bottom:4px solid var(--accent)}}h1,h2,h3,h4{{line-height:1.25}}h1{{margin-bottom:6px}}section{{margin:28px 0}}.muted,small{{color:var(--muted)}}.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(135px,1fr));gap:12px}}.metric{{border:1px solid var(--line);background:var(--panel);border-radius:10px;padding:13px}}.metric span{{display:block;color:var(--muted)}}.metric strong{{font-size:24px}}
.finding{{border:1px solid var(--line);border-radius:12px;padding:18px;margin:15px 0}}.finding-head{{display:flex;gap:12px;align-items:flex-start}}.finding h3{{margin:0 0 3px}}.severity{{font-weight:750;text-transform:uppercase;font-size:11px;padding:3px 7px;border-radius:999px;background:#eef2f6}}.severity.critical{{color:var(--critical)}}.severity.high{{color:var(--high)}}.severity.medium{{color:var(--medium)}}.severity.low{{color:var(--low)}}.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:20px}}.tag{{display:inline-block;background:#eef3ff;border-radius:5px;padding:3px 6px;margin:2px}}details{{margin-top:12px}}pre{{white-space:pre-wrap;overflow:auto;background:#f3f5f8;border-radius:7px;padding:9px}}.evidence li{{margin:8px 0}}table{{width:100%;border-collapse:collapse}}th,td{{border:1px solid var(--line);padding:8px;vertical-align:top;text-align:left}}th{{background:var(--panel)}}.scroll{{overflow:auto}}.empty{{padding:20px;border:1px dashed var(--line);color:var(--muted)}}
@media(max-width:760px){{header,main{{padding:18px}}.grid2{{grid-template-columns:1fr}}}}@media print{{header,main{{max-width:none;padding:16px}}.finding,section{{break-inside:avoid}}}}
</style></head><body>{body}</body></html>"""
