import json
import re
import subprocess
from pathlib import Path

import pytest

from ghaudit import exposure as ex
from ghaudit import secrets as sp
from ghaudit.cli import main
from ghaudit.incidents import INCIDENTS

ROOT = Path(__file__).resolve().parents[1]
TJ_BAD = "0e58ed8671d6b60d0890c21b07f8835ace038e67"


def wf(uses: str) -> str:
    return f"on: push\npermissions: {{}}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: {uses}\n"


def test_incident_table_is_well_formed():
    ids = [i.id for i in INCIDENTS]
    assert len(ids) == len(set(ids))
    for inc in INCIDENTS:
        assert inc.actions and inc.windows and inc.reference.startswith("https://")
        assert all(a == a.lower() or "/" in a for a in inc.actions)
        for start, end in inc.windows:
            assert start < end and start.tzinfo is not None
        assert all(re.fullmatch(r"[0-9a-f]{40}", s) for s in inc.malicious_shas)


def test_references_parser():
    text = "steps:\n  - uses: tj-actions/changed-files@v45 # pinned?\n  - uses: ./local\n  - uses: 'owner/repo/sub/path@abc'\n"
    assert ex.references(text) == [(2, "tj-actions/changed-files", "v45"), (4, "owner/repo", "abc")]


@pytest.mark.parametrize("uses,kind,sev", [
    (f"tj-actions/changed-files@{TJ_BAD}", "malicious-pin", "critical"),
    ("tj-actions/changed-files@v45", "hijackable-tag", "high"),
    ("Aquasecurity/trivy-action@0.28.0", "hijackable-tag", "high"),
    ("reviewdog/action-shellcheck@" + "a" * 40, "sha-pin", "medium"),     # pinning did not protect here
    ("tj-actions/changed-files@" + "a" * 40, "sha-pin", "info"),
])
def test_current_references(uses, kind, sev):
    found = ex.scan_files({".github/workflows/ci.yml": wf(uses)})
    assert [(e.kind, e.severity) for e in found] == [(kind, sev)]


def test_unrelated_actions_are_ignored():
    assert ex.scan_files({".github/workflows/ci.yml": wf("actions/checkout@v5")}) == []


def test_worm_files():
    files = {
        ".github/workflows/shai-hulud-workflow.yml": "on: push",
        ".github/workflows/discussion.yaml": "on: discussion\njobs:\n  x:\n    runs-on: self-hosted\n    steps:\n      - run: echo ${{ github.event.discussion.body }}\n",
        ".github/workflows/formatter_123.yml": "steps:\n  - run: echo '${{ toJSON(secrets) }}' > format.json\n",
        ".github/workflows/formatter_ok.yml": "steps:\n  - run: prettier --check .\n",          # innocent formatter
        ".github/workflows/discussion.yml": "on: discussion\n",                                  # innocent name
    }
    found = {e.file for e in ex.scan_files(files) if e.kind == "worm-file"}
    assert found == {".github/workflows/shai-hulud-workflow.yml", ".github/workflows/discussion.yaml",
                     ".github/workflows/formatter_123.yml"}


def git(repo, *args, date=None):
    env = None
    if date:
        import os
        env = {**os.environ, "GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date}
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=env)


def make_history(tmp_path):
    repo = tmp_path / "app"
    (repo / ".github" / "workflows").mkdir(parents=True)
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "t@example.com")
    git(repo, "config", "user.name", "T")
    f = repo / ".github" / "workflows" / "ci.yml"
    f.write_text(wf("tj-actions/changed-files@v44"))
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "ci", date="2025-01-10T10:00:00Z")
    f.write_text(wf("tj-actions/changed-files@" + "b" * 40))          # pinned after the incident
    git(repo, "commit", "-qam", "pin", date="2025-03-20T10:00:00Z")
    return repo


def test_history_finds_use_during_window(tmp_path):
    repo = make_history(tmp_path)
    assert [e.kind for e in ex.scan_files(ex.local_files(str(repo)))] == ["sha-pin"]   # fine today...
    hist = ex.scan_history(str(repo))                                                  # ...but not in March 2025
    assert len(hist) == 1 and hist[0].incident == "CVE-2025-30066" and hist[0].severity == "high"
    assert "tj-actions/changed-files@v44" in hist[0].message


def test_history_outside_git_is_empty(tmp_path):
    assert ex.scan_history(str(tmp_path)) == []


class FakeClient:
    def __init__(self, counts):
        self.counts, self.calls = counts, []

    def get(self, path):
        self.calls.append(path)
        return {"total_count": self.counts.pop(0)}


def test_runs_during_window():
    c = FakeClient([3])
    found = ex.scan_runs("acme/app", c, {"CVE-2025-30066"})
    assert found[0].severity == "critical" and "3 workflow run" in found[0].message
    assert "created=2025-03-14T00:00:00Z..2025-03-15T23:59:59Z" in c.calls[0]
    assert ex.scan_runs("acme/app", FakeClient([0]), {"CVE-2025-30066"})[0].severity == "info"


def test_cli_exposure_on_examples_and_history(tmp_path, capsys):
    assert main(["exposure", str(ROOT), "--workflows-dir", "examples/before/workflows", "--no-history", "--fail-on-exposure"]) == 1
    assert "tj-actions/changed-files@v45" in capsys.readouterr().out
    repo = make_history(tmp_path)
    out = tmp_path / "e.json"
    assert main(["exposure", str(repo), "--format", "json", "-o", str(out)]) == 0
    data = json.loads(out.read_text())
    assert {f["kind"] for f in data["findings"]} == {"sha-pin", "used-during-window"}


# ------------------------------------------------------------------ rotation plan
def test_secrets_plan_never_contains_values(tmp_path):
    gl = tmp_path / "gl.json"
    gl.write_text(json.dumps([
        {"RuleID": "aws-access-token", "Description": "AWS", "File": ".env", "StartLine": 1, "Commit": "abc123def4567",
         "Date": "2025-01-02T03:04:05Z", "Author": "dev", "Secret": "REDACTED", "Match": "REDACTED"},
        {"RuleID": "generic-api-key", "Description": "Generic", "File": ".env", "StartLine": 2, "Commit": "abc123def4567",
         "Date": "2025-01-02T03:04:05Z", "Author": "dev", "Secret": "REDACTED"},
        {"RuleID": "slack-webhook-url", "Description": "Slack", "File": "app.py", "StartLine": 9, "Commit": "999", "Date": "2025-02-01"},
    ]))
    th = tmp_path / "th.jsonl"
    th.write_text(json.dumps({"DetectorName": "Postgres", "SourceMetadata": {"Data": {"Git": {
        "file": "db.txt", "line": 3, "commit": "777", "timestamp": "2025-03-01 10:00:00", "email": "x@y"}}}}) + "\nnot json\n")
    leaks = sp.dedupe(sp.from_gitleaks(gl) + sp.from_trufflehog(th))
    assert [lk.priority for lk in leaks] == [1, 1, 2, 3]      # the generic key next to an AWS key is boosted
    csv_text, md = sp.to_csv(leaks), sp.to_markdown("acme/app", leaks)
    assert csv_text.splitlines()[0].startswith("#,rotate,secret type")
    assert "REDACTED" not in csv_text + md and "4 possible secret(s)" in md
    assert main(["secrets-plan", "--gitleaks", str(gl), "--csv", str(tmp_path / "p.csv"), "--md", str(tmp_path / "s.md")]) == 0
    assert (tmp_path / "p.csv").read_text().count("\n") == 4


def test_history_scan_script_never_verifies():
    text = (ROOT / "tools" / "secrets-history-scan.sh").read_text()
    assert "--no-verification" in text and "--redact" in text and "--mirror" in text


def test_demo_repo_script_builds_history_with_findings(tmp_path):
    repo = tmp_path / "acme-app"
    subprocess.run(["bash", str(ROOT / "tools" / "make-secrets-demo-repo.sh"), str(repo)], check=True, capture_output=True)
    assert not (repo / ".env").exists()                       # gone from the latest code...
    hist = ex.scan_history(str(repo))                          # ...but the workflow history still shows the window
    assert [e.incident for e in hist] == ["CVE-2025-30066"]
    log = subprocess.run(["git", "-C", str(repo), "log", "--all", "-p"], capture_output=True, text=True).stdout
    assert "AKIAQZ4DEMONOTREAL7X" in log and "DEMO ONLY" in log
