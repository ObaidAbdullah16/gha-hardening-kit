"""Output formats: text, json, markdown, sarif, html."""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Any

from . import __version__
from .model import SEVERITY_ORDER, Finding, RepoContext
from .rules import RULES
from .scoring import grade, score, summary

SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}


def result_dict(ctx: RepoContext, findings: list[Finding], scored: list[Finding] | None = None) -> dict[str, Any]:
    """`scored`: the findings the score is computed from (all of them), when `findings` is a filtered view."""
    s = score(findings if scored is None else scored)
    return {
        "tool": "ghaudit",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "repository": ctx.name,
        "workflows_scanned": len(ctx.workflows),
        "score": s,
        "grade": grade(s),
        "counts": summary(findings),
        "findings": [f.to_dict() for f in findings],
        "findings_hidden": 0 if scored is None else len(scored) - len(findings),
    }


def to_json(ctx: RepoContext, findings: list[Finding], scored: list[Finding] | None = None) -> str:
    return json.dumps(result_dict(ctx, findings, scored), indent=2)


def to_text(ctx: RepoContext, findings: list[Finding], scored: list[Finding] | None = None) -> str:
    r = result_dict(ctx, findings, scored)
    lines = [
        f"ghaudit {__version__}  repository: {ctx.name}  workflows: {r['workflows_scanned']}",
        f"SCORE {r['score']}/100  GRADE {r['grade']}  "
        + "  ".join(f"{k}={v}" for k, v in r["counts"].items() if v),
    ]
    if r["findings_hidden"]:
        lines.append(f"({r['findings_hidden']} lower-severity finding(s) hidden by --min-severity; the score counts them)")
    lines.append("")
    for f in sorted(findings, key=lambda x: (-SEVERITY_ORDER[x.severity], x.file, x.line)):
        lines.append(f"[{f.severity.upper():8}] {f.rule_id} {f.file}:{f.line}  {f.message}")
    if not findings:
        lines.append("No findings. Nice.")
    return "\n".join(lines)


def to_markdown(ctx: RepoContext, findings: list[Finding], title: str | None = None, scored: list[Finding] | None = None) -> str:
    r = result_dict(ctx, findings, scored)
    out = [
        f"## {title or 'GitHub Actions security audit'}: `{ctx.name}`",
        "",
        f"**Score: {r['score']}/100 (grade {r['grade']})** | workflows scanned: {r['workflows_scanned']} | "
        + ", ".join(f"{k}: {v}" for k, v in r["counts"].items() if v),
        "",
    ]
    if not findings:
        out.append("No findings.")
        return "\n".join(out)
    out += ["| Severity | Rule | Location | Finding |", "|---|---|---|---|"]
    for f in sorted(findings, key=lambda x: (-SEVERITY_ORDER[x.severity], x.file, x.line)):
        out.append(f"| {f.severity} | {f.rule_id} {RULES[f.rule_id].name} | `{f.file}:{f.line}` | {f.message.replace('|', '/')} |")
    out += ["", "### How to fix", ""]
    for rid in sorted({f.rule_id for f in findings}):
        rule = RULES[rid]
        ref = f" ([reference]({rule.reference}))" if rule.reference else ""
        out.append(f"- **{rid} {rule.name}**: {rule.fix}{ref}")
    return "\n".join(out)


def to_sarif(ctx: RepoContext, findings: list[Finding], scored: list[Finding] | None = None) -> str:
    used = sorted({f.rule_id for f in findings}) or []
    rules = []
    for rid in sorted(RULES):
        rule = RULES[rid]
        rules.append({
            "id": rid,
            "name": rule.name,
            "shortDescription": {"text": rule.summary},
            "fullDescription": {"text": rule.summary},
            "help": {"text": rule.fix, "markdown": rule.fix},
            "helpUri": rule.reference or "https://github.com/ObaidAbdullah16/gha-hardening-kit",
            "properties": {"security-severity": SECURITY_SEVERITY[rule.severity], "tags": ["security", "github-actions"]},
        })
    results = []
    for f in findings:
        results.append({
            "ruleId": f.rule_id,
            "ruleIndex": sorted(RULES).index(f.rule_id),
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": max(1, f.line)},
                }
            }],
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "ghaudit", "version": __version__,
                                "informationUri": "https://github.com/ObaidAbdullah16/gha-hardening-kit",
                                "rules": rules}},
            "results": results,
            "properties": {"rulesTriggered": used},
        }],
    }
    return json.dumps(doc, indent=2)


_CSS = """
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f6f7f9;color:#1d2330}
main{max-width:1000px;margin:0 auto;padding:24px 16px}
.banner{background:#fff3cd;border:1px solid #e6c766;padding:8px 12px;border-radius:6px;font-size:14px}
.cards{display:flex;gap:16px;flex-wrap:wrap;margin:16px 0}
.card{background:#fff;border:1px solid #dde1e7;border-radius:10px;padding:16px;flex:1;min-width:260px}
.score{font-size:44px;font-weight:700}
.A{color:#1a7f37}.B{color:#4c8c2b}.C{color:#9a6700}.D{color:#bc4c00}.F{color:#cf222e}
table{width:100%;border-collapse:collapse;background:#fff;font-size:14px}
th,td{border-bottom:1px solid #e3e6ea;padding:6px 8px;text-align:left;vertical-align:top}
th{background:#eef1f5}
.sev{font-weight:600;text-transform:uppercase;font-size:12px}
.critical{color:#8b0000}.high{color:#cf222e}.medium{color:#bc4c00}.low{color:#57606a}.info{color:#57606a}
code{background:#eef1f5;padding:1px 4px;border-radius:4px}
@media (prefers-color-scheme: dark){body{background:#0d1117;color:#e6edf3}.card,table{background:#161b22;border-color:#30363d}
th{background:#21262d}td,th{border-color:#30363d}code{background:#21262d}.banner{background:#3b2f00;border-color:#6b5500}}
"""


def to_html(reports: list[tuple[str, RepoContext, list[Finding]]], title: str = "GitHub Actions hardening report",
            banner: str = "") -> str:
    """One page comparing one or more scans (e.g. before vs after)."""
    cards, sections = [], []
    for label, ctx, findings in reports:
        r = result_dict(ctx, findings)
        counts = ", ".join(f"{k}: {v}" for k, v in r["counts"].items() if v) or "no findings"
        cards.append(
            f'<div class="card"><div>{html.escape(label)}</div>'
            f'<div class="score {r["grade"]}">{r["score"]}/100 &middot; {r["grade"]}</div>'
            f'<div>{r["workflows_scanned"]} workflow(s) &middot; {html.escape(counts)}</div></div>'
        )
        rows = "".join(
            f'<tr><td class="sev {f.severity}">{f.severity}</td><td>{f.rule_id}<br><small>{RULES[f.rule_id].name}</small></td>'
            f"<td><code>{html.escape(f.file)}:{f.line}</code></td><td>{html.escape(f.message)}</td>"
            f"<td>{html.escape(RULES[f.rule_id].fix)}</td></tr>"
            for f in sorted(findings, key=lambda x: (-SEVERITY_ORDER[x.severity], x.file, x.line))
        ) or '<tr><td colspan="5">No findings.</td></tr>'
        sections.append(
            f"<h2>{html.escape(label)}</h2><table><thead><tr><th>Severity</th><th>Rule</th><th>Location</th>"
            f"<th>Finding</th><th>Fix</th></tr></thead><tbody>{rows}</tbody></table>"
        )
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    banner_html = f'<p class="banner">{html.escape(banner)}</p>' if banner else ""
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{html.escape(title)}</title><style>{_CSS}</style></head><body><main>"
        f"<h1>{html.escape(title)}</h1>{banner_html}<div class='cards'>{''.join(cards)}</div>"
        f"{''.join(sections)}<p><small>Generated by ghaudit {__version__} on {generated}.</small></p>"
        "</main></body></html>"
    )
