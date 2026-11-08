"""The shipped before/after examples must keep demonstrating a big improvement."""
from pathlib import Path

from ghaudit.loader import load_local
from ghaudit.rules import audit
from ghaudit.scoring import score

ROOT = Path(__file__).resolve().parents[1]


def test_before_is_terrible_after_is_good():
    before = audit(load_local(str(ROOT), str(ROOT / "examples/before/workflows")))
    after = audit(load_local(str(ROOT), str(ROOT / "examples/after/workflows")))
    assert score(before) < 20
    # Only unpinned references may remain in "after" (they are pinned by tools/pin_actions.py at publish time)
    assert {f.rule_id for f in after} <= {"GHA001"}
    rules_before = {f.rule_id for f in before}
    for rid in ["GHA001", "GHA002", "GHA003", "GHA004", "GHA005", "GHA006", "GHA010", "GHA011", "GHA013", "GHA014"]:
        assert rid in rules_before, rid
