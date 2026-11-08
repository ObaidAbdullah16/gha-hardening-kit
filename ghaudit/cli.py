"""Command line interface.

    ghaudit scan .                              # this repo, text output
    ghaudit scan --repo owner/name              # any public GitHub repo (set GH_TOKEN for higher rate limits)
    ghaudit scan . --format sarif -o ghaudit.sarif
    ghaudit scan . --fail-under 80              # exit 1 if score < 80 (use in CI)
    ghaudit compare --before DIR --after DIR --html report.html
    ghaudit exposure .                          # known supply-chain incidents: references, git history, worm files
    ghaudit exposure . --repo owner/name        # + workflow runs during each incident window (GitHub API)
    ghaudit secrets-plan --gitleaks gl.json --name owner/repo --csv rotation-plan.csv --md summary.md
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .loader import load_github, load_local
from .report import to_html, to_json, to_markdown, to_sarif, to_text
from .rules import RULES, audit
from .scoring import score

FORMATS = {"text": to_text, "json": to_json, "md": to_markdown, "sarif": to_sarif}


def _write(text: str, out: str | None) -> None:
    if out:
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(text + ("\n" if not text.endswith("\n") else ""), encoding="utf-8")
    else:
        print(text)


def cmd_scan(a: argparse.Namespace) -> int:
    ctx = load_github(a.repo) if a.repo else load_local(a.path, a.workflows_dir)
    findings = audit(ctx)
    shown = findings
    if a.min_severity:
        from .model import SEVERITY_ORDER
        shown = [f for f in findings if SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[a.min_severity]]
    # --min-severity only hides findings from the output. The score and the --fail-under gate
    # always count everything, so a filter can't turn a failing pipeline green.
    _write(FORMATS[a.format](ctx, shown, scored=findings), a.output)
    if a.fail_under is not None and score(findings) < a.fail_under:
        print(f"score {score(findings)} is below --fail-under {a.fail_under}", file=sys.stderr)
        return 1
    return 0


def cmd_compare(a: argparse.Namespace) -> int:
    before = load_local(a.root, a.before)
    after = load_local(a.root, a.after)
    fb, fa = audit(before), audit(after)
    if a.html:
        Path(a.html).parent.mkdir(parents=True, exist_ok=True)
        Path(a.html).write_text(
            to_html([("Before hardening", before, fb), ("After hardening", after, fa)],
                    title=a.title, banner=a.banner), encoding="utf-8")
    if a.markdown:
        md = to_markdown(before, fb, "Before") + "\n\n" + to_markdown(after, fa, "After")
        _write(md, a.markdown)
    print(f"before: {score(fb)}/100   after: {score(fa)}/100")
    return 0


def cmd_exposure(a: argparse.Namespace) -> int:
    from . import exposure as ex
    from .loader import GitHubClient

    found: list = []
    if a.path_given or not a.repo:
        found += ex.scan_files(ex.local_files(a.path, a.workflows_dir))
        if not a.no_history:
            found += ex.scan_history(a.path)
        name = Path(a.path).resolve().name
    else:
        ctx = load_github(a.repo)
        found += ex.scan_files({w.path: w.text for w in ctx.workflows})
        name = a.repo
    if a.repo:
        touched = {e.incident for e in found if e.kind in ("hijackable-tag", "malicious-pin", "used-during-window")}
        found += ex.scan_runs(a.repo, GitHubClient(), touched)
        name = a.repo
    render = {"text": ex.to_text, "md": ex.to_markdown, "json": ex.to_json}[a.format]
    _write(render(name, found), a.output)
    bad = [e for e in found if e.severity in ("critical", "high")]
    return 1 if (a.fail_on_exposure and bad) else 0


def cmd_secrets_plan(a: argparse.Namespace) -> int:
    from . import secrets as sp

    leaks = []
    if a.gitleaks:
        leaks += sp.from_gitleaks(a.gitleaks)
    if a.trufflehog:
        leaks += sp.from_trufflehog(a.trufflehog)
    leaks = sp.dedupe(leaks)
    if a.csv:
        _write(sp.to_csv(leaks), a.csv)
    _write(sp.to_markdown(a.name, leaks), a.md)
    return 0


def cmd_rules(_: argparse.Namespace) -> int:
    for rid, r in sorted(RULES.items()):
        print(f"{rid}  {r.severity:8} {r.name:32} {r.summary}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="ghaudit", description="Score GitHub Actions workflows for supply-chain risks.")
    ap.add_argument("--version", action="version", version=f"ghaudit {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a local repo folder or a GitHub repo")
    s.add_argument("path", nargs="?", default=".", help="repository folder (default: .)")
    s.add_argument("--repo", help="owner/name of a GitHub repository to scan via the API")
    s.add_argument("--workflows-dir", help="read workflows from this folder instead of .github/workflows")
    s.add_argument("--format", choices=sorted(FORMATS), default="text")
    s.add_argument("-o", "--output", help="write to a file instead of stdout")
    s.add_argument("--fail-under", type=int, help="exit 1 when the score is below this value")
    s.add_argument("--min-severity", choices=["info", "low", "medium", "high", "critical"])
    s.set_defaults(func=cmd_scan)

    c = sub.add_parser("compare", help="before/after report for two folders of workflows")
    c.add_argument("--root", default=".", help="repository root (for dependabot/renovate detection)")
    c.add_argument("--before", required=True)
    c.add_argument("--after", required=True)
    c.add_argument("--html")
    c.add_argument("--markdown")
    c.add_argument("--title", default="GitHub Actions hardening: before vs after")
    c.add_argument("--banner", default="")
    c.set_defaults(func=cmd_compare)

    x = sub.add_parser("exposure", help="check exposure to known GitHub Actions supply-chain incidents")
    x.add_argument("path", nargs="?", default=None, help="local checkout (default: . unless only --repo is given)")
    x.add_argument("--repo", help="owner/name: also count workflow runs during each incident window (GitHub API)")
    x.add_argument("--no-history", action="store_true", help="skip the git-history check")
    x.add_argument("--workflows-dir", help="read workflow files from this folder (relative to path) instead of .github/")
    x.add_argument("--format", choices=["text", "md", "json"], default="text")
    x.add_argument("-o", "--output")
    x.add_argument("--fail-on-exposure", action="store_true", help="exit 1 when anything critical or high is found")
    x.set_defaults(func=cmd_exposure)

    sp_ = sub.add_parser("secrets-plan", help="rotation plan from gitleaks/TruffleHog history scans (no secret values)")
    sp_.add_argument("--gitleaks", help="gitleaks JSON report (run with --redact)")
    sp_.add_argument("--trufflehog", help="TruffleHog JSON-lines output (run with --no-verification)")
    sp_.add_argument("--name", default="repository", help="repository name shown in the summary")
    sp_.add_argument("--csv", help="write the rotation plan CSV here")
    sp_.add_argument("--md", help="write the Markdown summary here (default: stdout)")
    sp_.set_defaults(func=cmd_secrets_plan)

    r = sub.add_parser("rules", help="list all rules")
    r.set_defaults(func=cmd_rules)

    a = ap.parse_args(argv)
    if a.cmd == "exposure":
        a.path_given = a.path is not None
        a.path = a.path or "."
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
