"""Data model: rules, findings and parsed workflow files."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEVERITY_WEIGHT = {"critical": 25, "high": 12, "medium": 6, "low": 2, "info": 0}


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str
    summary: str
    fix: str
    reference: str = ""


@dataclass
class Finding:
    rule_id: str
    severity: str
    file: str
    line: int
    message: str
    job: str = ""
    step: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class WorkflowFile:
    path: str            # path shown in reports, e.g. .github/workflows/ci.yml
    text: str            # raw YAML text
    data: dict[str, Any] = field(default_factory=dict)
    parse_error: str = ""
    # Exact 1-based line of every key and list item, e.g. ("jobs", "build", "steps", 0, "run") -> 12.
    node_lines: dict[tuple[Any, ...], int] = field(default_factory=dict)

    @property
    def lines(self) -> list[str]:
        return self.text.splitlines()

    def line_of(self, *path: Any, default: int = 1) -> int:
        """Line where a key or list item starts, e.g. line_of("jobs", "build", "steps", 0)."""
        return self.node_lines.get(tuple(path), default)

    def find_line(self, needle: str, start: int = 1) -> int:
        """1-based line number of the first line (>= start) containing needle, else start."""
        for i, ln in enumerate(self.lines[start - 1 :], start=start):
            if needle in ln:
                return i
        return max(start, 1)


@dataclass
class RepoContext:
    """Everything the rules need about one repository."""
    name: str
    workflows: list[WorkflowFile]
    has_dependabot_actions: bool = False
    has_renovate: bool = False
    is_public: bool = True
