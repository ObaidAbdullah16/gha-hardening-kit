"""`ghaudit secrets-plan`: turn gitleaks / TruffleHog history-scan output into a rotation plan.

The plan never contains a secret value: only its type, where it was committed, by whom and when.
TruffleHog must be run with `--no-verification` (see docs/secrets-addon.md: we never *use* a credential
to find out whether it works).
"""
from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass
from pathlib import Path

# Rotation order: 1 = today (cloud, CI/CD, source control, payments), 2 = this week (data stores), 3 = next.
PRIORITY_WORDS = (
    (1, ("aws", "gcp", "google-cloud", "azure", "github", "gitlab", "npm", "pypi", "docker", "private-key", "privatekey",
         "stripe", "razorpay", "paypal", "openai", "anthropic", "terraform", "vault", "heroku", "digitalocean")),
    (2, ("postgres", "mysql", "mongodb", "redis", "database", "jdbc", "uri", "connection", "sendgrid", "mailgun", "twilio", "smtp")),
)


@dataclass
class Leak:
    rule: str
    description: str
    file: str
    line: int
    commit: str
    date: str
    author: str
    source: str           # gitleaks | trufflehog
    boost: int = 0        # set by dedupe(): found in the same commit and file as a higher-priority secret

    @property
    def kind(self) -> str:
        return self.rule or self.description

    @property
    def priority(self) -> int:
        if self.boost:
            return self.boost
        text = f"{self.rule} {self.description}".lower()
        for prio, words in PRIORITY_WORDS:
            if any(w in text for w in words):
                return prio
        return 3


def from_gitleaks(path: str | Path) -> list[Leak]:
    data = json.loads(Path(path).read_text(encoding="utf-8") or "[]")
    return [Leak(rule=d.get("RuleID", ""), description=d.get("Description", ""), file=d.get("File", ""),
                 line=int(d.get("StartLine") or 0), commit=d.get("Commit", "")[:12], date=(d.get("Date") or "")[:10],
                 author=d.get("Author", ""), source="gitleaks") for d in data if isinstance(d, dict)]


def from_trufflehog(path: str | Path) -> list[Leak]:
    out = []
    for ln in Path(path).read_text(encoding="utf-8").splitlines():
        if not ln.strip().startswith("{"):
            continue
        d = json.loads(ln)
        git = ((d.get("SourceMetadata") or {}).get("Data") or {}).get("Git") or {}
        out.append(Leak(rule=str(d.get("DetectorName", "")), description=f"{d.get('DetectorName', '')} (unverified)",
                        file=git.get("file", ""), line=int(git.get("line") or 0), commit=str(git.get("commit", ""))[:12],
                        date=str(git.get("timestamp", ""))[:10], author=git.get("email", ""), source="trufflehog"))
    return out


def dedupe(leaks: list[Leak]) -> list[Leak]:
    """One row per location; a secret committed next to a cloud key (same commit and file) inherits its urgency."""
    best: dict[tuple[str, str], int] = {}
    for lk in leaks:
        k = (lk.commit, lk.file)
        best[k] = min(best.get(k, 3), lk.priority)
    for lk in leaks:
        if best[(lk.commit, lk.file)] < lk.priority:
            lk.boost = best[(lk.commit, lk.file)]
    seen, out = set(), []
    for lk in sorted(leaks, key=lambda x: (x.priority, x.file, x.line, x.date)):
        key = (lk.file, lk.line, lk.commit)
        if key not in seen:
            seen.add(key)
            out.append(lk)
    return out


PLAN_COLUMNS = ["#", "rotate", "secret type", "detected by", "file", "line", "commit", "committed on", "committed by",
                "still in latest code? (y/n)", "owner", "used by (systems)", "blast radius", "rotated on", "old one revoked on",
                "owner confirmed working"]


def to_csv(leaks: list[Leak]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(PLAN_COLUMNS)
    when = {1: "1 - today", 2: "2 - this week", 3: "3 - next"}
    for i, lk in enumerate(leaks, start=1):
        w.writerow([i, when[lk.priority], lk.kind, lk.source, lk.file, lk.line, lk.commit, lk.date, lk.author,
                    "", "", "", "", "", "", ""])
    return buf.getvalue()


def to_markdown(repo: str, leaks: list[Leak]) -> str:
    out = [f"## Secrets in git history: `{repo}`", ""]
    if not leaks:
        return "\n".join(out + ["No secrets found in the history scan.", ""])
    counts = {p: sum(1 for lk in leaks if lk.priority == p) for p in (1, 2, 3)}
    out += [f"**{len(leaks)} possible secret(s)**: {counts[1]} to rotate today, {counts[2]} this week, {counts[3]} next.",
            "Values are not shown and were not tested. Every one stays valid until its owner rotates it - deleting the",
            "commit does not help, because clones and forks keep it.", "",
            "| Rotate | Type | File | Commit | Date |", "|---|---|---|---|---|"]
    for lk in leaks:
        out.append(f"| {lk.priority} | {lk.kind} | `{lk.file}:{lk.line}` | `{lk.commit}` | {lk.date} |")
    out += ["", "Next: fill in owner, systems and blast radius in `rotation-plan.csv`, rotate in that order, confirm each",
            "service still works, then revoke the old credential. Turn on secret scanning with push protection."]
    return "\n".join(out) + "\n"
