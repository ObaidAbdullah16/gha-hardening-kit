import pin_actions

SHA = "0123456789abcdef0123456789abcdef01234567"


class FakeResolver:
    def __init__(self):
        self.calls = []

    def resolve(self, repo, ref):
        self.calls.append((repo, ref))
        return SHA


def test_pins_simple_uses():
    r = FakeResolver()
    new, note = pin_actions.process_line("      - uses: actions/checkout@v7\n", r)
    assert new == f"      - uses: actions/checkout@{SHA} # v7\n"
    assert r.calls == [("actions/checkout", "v7")]
    assert "->" in note


def test_subpath_action_resolves_repo_only():
    r = FakeResolver()
    new, _ = pin_actions.process_line("        uses: github/codeql-action/upload-sarif@v4", r)
    assert new == f"        uses: github/codeql-action/upload-sarif@{SHA} # v4"
    assert r.calls == [("github/codeql-action", "v4")]


def test_quoted_and_comment_replaced():
    r = FakeResolver()
    new, _ = pin_actions.process_line("  - uses: 'docker/login-action@v4'  # login\n", r)
    assert new == f"  - uses: 'docker/login-action@{SHA}' # v4\n"


def test_skips_local_docker_and_already_pinned():
    r = FakeResolver()
    for line in [
        "  - uses: ./.github/actions/x",
        "  - uses: docker://alpine:3.20",
        f"  - uses: actions/checkout@{SHA} # v7",
        "    run: echo uses: something@v1",
    ]:
        new, note = pin_actions.process_line(line, r)
        assert new == line and note is None
    assert r.calls == []


def test_check_mode_reports(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v7\n")
    assert pin_actions.main(["--check", str(tmp_path)]) == 1
    (wf / "ci.yml").write_text(f"jobs:\n  a:\n    steps:\n      - uses: actions/checkout@{SHA} # v7\n")
    assert pin_actions.main(["--check", str(tmp_path)]) == 0


def test_extra_globs_file(tmp_path):
    (tmp_path / "examples").mkdir()
    (tmp_path / "examples" / "x.yml").write_text("- uses: a/b@v1\n")
    (tmp_path / ".pin-actions").write_text("# comment\nexamples/*.yml\n")
    files = pin_actions.files_in(tmp_path)
    assert [f.name for f in files] == ["x.yml"]
