#!/usr/bin/env python3
"""Pin GitHub Actions `uses:` references to full commit SHAs.

    uses: actions/checkout@v7
becomes
    uses: actions/checkout@<40-char-sha> # v7

Why: tags are mutable. In the tj-actions (2025) and trivy-action (2026) incidents,
attackers moved existing tags to malicious commits. A SHA cannot be moved.

Usage:
    python3 tools/pin_actions.py --write  path/to/repo [more repos...]
    python3 tools/pin_actions.py --check  path/to/repo        # exit 1 if anything is unpinned

Files scanned in each path:
    .github/workflows/*.yml|yaml, .github/actions/**/action.yml|yaml, action.yml|yaml
    plus any glob listed (one per line) in a `.pin-actions` file at the repo root.

Auth: set GH_TOKEN or GITHUB_TOKEN (e.g. GH_TOKEN=$(gh auth token)). Without a token
GitHub allows only 60 API requests per hour.

Standard library only, so it runs anywhere Python 3.9+ runs.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
# `uses:` line, optionally inside a list item, optionally quoted, optional trailing comment
USES_RE = re.compile(
    r"""^(?P<prefix>\s*(?:-\s+)?uses:\s*)(?P<q>['"]?)(?P<target>[^@\s'"#]+)@(?P<ref>[^\s'"#]+)(?P=q)(?P<comment>\s*#.*)?\s*$"""
)
API = os.environ.get("GITHUB_API_URL", "https://api.github.com")


class Resolver:
    def __init__(self, token: str | None):
        self.token = token
        self.cache: dict[tuple[str, str], str] = {}

    def resolve(self, repo: str, ref: str) -> str:
        key = (repo, ref)
        if key in self.cache:
            return self.cache[key]
        req = urllib.request.Request(f"{API}/repos/{repo}/commits/{ref}")
        # This media type makes the API return only the SHA as plain text
        req.add_header("Accept", "application/vnd.github.sha")
        req.add_header("User-Agent", "pin-actions")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                sha = resp.read().decode().strip()
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"cannot resolve {repo}@{ref}: HTTP {e.code}") from e
        if not SHA_RE.match(sha):
            raise RuntimeError(f"unexpected response for {repo}@{ref}: {sha[:80]!r}")
        self.cache[key] = sha
        return sha


def files_in(root: Path) -> list[Path]:
    patterns = [
        ".github/workflows/*.yml",
        ".github/workflows/*.yaml",
        ".github/actions/**/action.yml",
        ".github/actions/**/action.yaml",
        "action.yml",
        "action.yaml",
    ]
    extra = root / ".pin-actions"
    if extra.exists():
        patterns += [ln.strip() for ln in extra.read_text().splitlines() if ln.strip() and not ln.startswith("#")]
    found: list[Path] = []
    for pat in patterns:
        for f in glob.glob(str(root / pat), recursive=True):
            p = Path(f)
            if p.is_file() and p not in found:
                found.append(p)
    return sorted(found)


def process_line(line: str, resolver: Resolver | None) -> tuple[str, str | None]:
    """Return (new_line, description_of_change_or_None). resolver=None means check only."""
    m = USES_RE.match(line.rstrip("\n"))
    if not m:
        return line, None
    target, ref = m.group("target"), m.group("ref")
    if target.startswith("./") or target.startswith("docker://"):
        return line, None
    if SHA_RE.match(ref):
        return line, None
    parts = target.split("/")
    if len(parts) < 2:
        return line, None
    repo = "/".join(parts[:2])
    if resolver is None:
        return line, f"{target}@{ref} is not pinned"
    sha = resolver.resolve(repo, ref)
    newline = f"{m.group('prefix')}{m.group('q')}{target}@{sha}{m.group('q')} # {ref}"
    if line.endswith("\n"):
        newline += "\n"
    return newline, f"{target}@{ref} -> {sha[:12]}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="rewrite files in place")
    mode.add_argument("--check", action="store_true", help="only report; exit 1 if anything is unpinned")
    ap.add_argument("paths", nargs="+", help="repository folders (or single workflow files)")
    args = ap.parse_args(argv)

    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    resolver = Resolver(token) if args.write else None
    problems = 0
    errors = 0

    for raw in args.paths:
        p = Path(raw)
        targets = [p] if p.is_file() else files_in(p)
        for f in targets:
            original = f.read_text(encoding="utf-8")
            out_lines = []
            changed = False
            for line in original.splitlines(keepends=True):
                try:
                    new, note = process_line(line, resolver)
                except RuntimeError as e:
                    print(f"  ! {f}: {e}", file=sys.stderr)
                    errors += 1
                    new, note = line, None
                if note:
                    problems += 1
                    print(f"  {f}: {note}")
                    changed = changed or new != line
                out_lines.append(new)
            if args.write and changed:
                f.write_text("".join(out_lines), encoding="utf-8")

    if args.check:
        print(f"{problems} unpinned reference(s)")
        return 1 if problems else 0
    print(json.dumps({"pinned": problems, "errors": errors}))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
