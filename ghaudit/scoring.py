"""Turn findings into a 0-100 score and a letter grade.

Each finding subtracts a weight by severity. To stop one noisy rule from dominating,
a rule can cost at most 3x its weight per file. The score is easy to explain to a
client: "you started at 100, unpinned actions cost you 24 points".
"""
from __future__ import annotations

from collections import defaultdict

from .model import SEVERITY_WEIGHT, Finding

MAX_HITS_PER_RULE_PER_FILE = 3


def score(findings: list[Finding]) -> int:
    hits: dict[tuple[str, str], int] = defaultdict(int)
    penalty = 0
    for f in findings:
        key = (f.file, f.rule_id)
        if hits[key] >= MAX_HITS_PER_RULE_PER_FILE:
            continue
        hits[key] += 1
        penalty += SEVERITY_WEIGHT.get(f.severity, 0)
    return max(0, 100 - penalty)


def grade(value: int) -> str:
    if value >= 90:
        return "A"
    if value >= 75:
        return "B"
    if value >= 60:
        return "C"
    if value >= 40:
        return "D"
    return "F"


def summary(findings: list[Finding]) -> dict[str, int]:
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        out[f.severity] = out.get(f.severity, 0) + 1
    return out
