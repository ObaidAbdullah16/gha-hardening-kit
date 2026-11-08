import json

from ghaudit.loader import parse_workflow
from ghaudit.model import RepoContext
from ghaudit.report import to_html, to_json, to_markdown, to_sarif, to_text
from ghaudit.rules import RULES, audit


def ctx_and_findings():
    wf = parse_workflow(".github/workflows/ci.yml", "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n")
    ctx = RepoContext(name="demo", workflows=[wf])
    return ctx, audit(ctx)


def test_sarif_is_valid_shape():
    ctx, f = ctx_and_findings()
    doc = json.loads(to_sarif(ctx, f))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert len(run["tool"]["driver"]["rules"]) == len(RULES)
    assert len(run["results"]) == len(f)
    for res in run["results"]:
        assert run["tool"]["driver"]["rules"][res["ruleIndex"]]["id"] == res["ruleId"]
        assert res["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1


def test_other_formats():
    ctx, f = ctx_and_findings()
    assert json.loads(to_json(ctx, f))["score"] < 100
    assert "SCORE" in to_text(ctx, f)
    assert "| Severity |" in to_markdown(ctx, f)
    page = to_html([("Before", ctx, f), ("After", ctx, [])], banner="demo <b>")
    assert "<!doctype html>" in page and "&lt;b&gt;" in page


def test_min_severity_hides_findings_but_not_from_the_score(tmp_path, capsys):
    from ghaudit.cli import main

    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    # medium (no permissions) + low (no timeout) + low (checkout keeps credentials), no dependabot (medium)
    (wf / "ci.yml").write_text("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
                               "      - uses: actions/checkout@" + "a" * 40 + "\n")
    assert main(["scan", str(tmp_path), "--fail-under", "90"]) == 1
    capsys.readouterr()
    # Hiding low/medium findings must not turn a failing gate green
    assert main(["scan", str(tmp_path), "--min-severity", "high", "--fail-under", "90"]) == 1
    out = capsys.readouterr().out
    assert "SCORE 84/100" in out and "hidden by --min-severity" in out
