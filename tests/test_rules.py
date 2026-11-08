import textwrap

from ghaudit.loader import parse_workflow
from ghaudit.model import RepoContext
from ghaudit.rules import audit
from ghaudit.scoring import grade, score

SHA = "a" * 40


def run(yaml_text, **ctx_kwargs):
    wf = parse_workflow(".github/workflows/t.yml", textwrap.dedent(yaml_text))
    ctx = RepoContext(name="t", workflows=[wf], has_dependabot_actions=True, **ctx_kwargs)
    return audit(ctx)


def ids(findings):
    return sorted({f.rule_id for f in findings})


def test_on_key_is_normalised():
    wf = parse_workflow("x.yml", "on: push\njobs: {}\n")
    assert wf.data["on"] == "push"


def test_clean_workflow_scores_100():
    f = run(f"""
        on: push
        permissions:
          contents: read
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 5
            steps:
              - uses: actions/checkout@{SHA} # v7
                with:
                  persist-credentials: false
              - run: make test
    """)
    assert f == []
    assert score(f) == 100 and grade(100) == "A"


def test_unpinned_third_party_is_high_first_party_medium():
    f = run("""
        on: push
        permissions: {}
        jobs:
          b:
            runs-on: ubuntu-latest
            timeout-minutes: 5
            steps:
              - uses: actions/setup-python@v6
              - uses: tj-actions/changed-files@v45
    """)
    sev = {x.message.split("`")[1]: x.severity for x in f if x.rule_id == "GHA001"}
    assert sev == {"actions/setup-python@v6": "medium", "tj-actions/changed-files@v45": "high"}


def test_docker_image_without_digest():
    f = run("""
        on: push
        permissions: {}
        jobs:
          b:
            runs-on: ubuntu-latest
            timeout-minutes: 5
            steps:
              - uses: docker://alpine:3.20
    """)
    assert ids(f) == ["GHA001"]


def test_missing_permissions_and_write_all():
    f = run("""
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            timeout-minutes: 5
            steps: [{run: echo}]
          b:
            runs-on: ubuntu-latest
            timeout-minutes: 5
            permissions: write-all
            steps: [{run: echo}]
    """)
    assert "GHA002" in ids(f) and "GHA003" in ids(f)


def test_pwn_request_detected():
    f = run(f"""
        on: pull_request_target
        permissions: {{}}
        jobs:
          t:
            runs-on: ubuntu-latest
            timeout-minutes: 5
            steps:
              - uses: actions/checkout@{SHA}
                with:
                  ref: ${{{{ github.event.pull_request.head.sha }}}}
                  persist-credentials: false
              - run: npm test
    """)
    assert [x.rule_id for x in f] == ["GHA004"]
    assert f[0].severity == "critical"


def test_pull_request_target_without_checkout_is_fine():
    f = run("""
        on: pull_request_target
        permissions: {}
        jobs:
          label:
            runs-on: ubuntu-latest
            timeout-minutes: 5
            steps:
              - run: echo labelling
    """)
    assert "GHA004" not in ids(f)


def test_script_injection_and_env_safe_form():
    bad = run("""
        on: issues
        permissions: {}
        jobs:
          t:
            runs-on: ubuntu-latest
            timeout-minutes: 5
            steps:
              - run: |
                  echo "${{ github.event.issue.title }}"
    """)
    good = run("""
        on: issues
        permissions: {}
        jobs:
          t:
            runs-on: ubuntu-latest
            timeout-minutes: 5
            steps:
              - env:
                  TITLE: ${{ github.event.issue.title }}
                run: echo "$TITLE"
    """)
    assert ids(bad) == ["GHA005"]
    assert good == []


def test_github_script_injection():
    f = run(f"""
        on: issue_comment
        permissions: {{}}
        jobs:
          t:
            runs-on: ubuntu-latest
            timeout-minutes: 5
            steps:
              - uses: actions/github-script@{SHA}
                with:
                  script: console.log(`${{{{ github.event.comment.body }}}}`)
    """)
    assert ids(f) == ["GHA005"]


def test_static_aws_keys_and_inline_secret():
    f = run(f"""
        on: push
        permissions: {{}}
        env:
          AWS_ACCESS_KEY_ID: ${{{{ secrets.AWS_ACCESS_KEY_ID }}}}
        jobs:
          d:
            runs-on: ubuntu-latest
            timeout-minutes: 5
            environment: prod
            steps:
              - uses: aws-actions/configure-aws-credentials@{SHA}
                with:
                  aws-secret-access-key: ${{{{ secrets.AWS_SECRET_ACCESS_KEY }}}}
                  aws-region: ap-south-1
              - run: curl -d x ${{{{ secrets.HOOK }}}}
    """)
    assert ids(f) == ["GHA006", "GHA014"]


def test_curl_pipe_shell():
    f = run("""
        on: push
        permissions: {}
        jobs:
          t:
            runs-on: ubuntu-latest
            timeout-minutes: 5
            steps:
              - run: curl -fsSL https://get.example.sh | sudo bash
    """)
    assert ids(f) == ["GHA010"]


def test_self_hosted_on_pr_and_secrets_inherit():
    f = run("""
        on: [pull_request]
        permissions: {}
        jobs:
          b:
            runs-on: [self-hosted, linux]
            timeout-minutes: 5
            steps: [{run: make}]
          p:
            uses: vendor/wf/.github/workflows/x.yml@main
            secrets: inherit
    """)
    assert {"GHA011", "GHA007", "GHA001"} <= set(ids(f))


def test_unsecure_commands_and_timeout():
    f = run("""
        on: push
        permissions: {}
        env:
          ACTIONS_ALLOW_UNSECURE_COMMANDS: true
        jobs:
          t:
            runs-on: ubuntu-latest
            steps: [{run: echo}]
    """)
    assert ids(f) == ["GHA009", "GHA013"]


def test_checkout_persist_credentials():
    f = run(f"""
        on: push
        permissions: {{}}
        jobs:
          t:
            runs-on: ubuntu-latest
            timeout-minutes: 5
            steps:
              - uses: actions/checkout@{SHA}
    """)
    assert ids(f) == ["GHA008"]


def test_workflow_run_artifact_poisoning():
    f = run(f"""
        on:
          workflow_run:
            workflows: [CI]
            types: [completed]
        permissions: {{}}
        jobs:
          t:
            runs-on: ubuntu-latest
            timeout-minutes: 5
            steps:
              - uses: actions/download-artifact@{SHA}
                with:
                  run-id: ${{{{ github.event.workflow_run.id }}}}
    """)
    assert ids(f) == ["GHA015"]


def test_deploy_without_environment():
    f = run(f"""
        on: push
        permissions: {{}}
        jobs:
          d:
            runs-on: ubuntu-latest
            timeout-minutes: 5
            permissions:
              id-token: write
            steps:
              - uses: aws-actions/configure-aws-credentials@{SHA}
                with:
                  role-to-assume: arn:aws:iam::123456789012:role/x
                  aws-region: ap-south-1
    """)
    assert ids(f) == ["GHA016"]


def test_no_dependabot_is_reported_once():
    wf = parse_workflow("a.yml", "on: push\npermissions: {}\njobs: {}\n")
    f = audit(RepoContext(name="t", workflows=[wf, wf]))
    assert [x.rule_id for x in f] == ["GHA012"]


def test_parse_error_is_info():
    f = run("on: push\njobs:\n  a: [unclosed\n")
    assert ids(f) == ["GHA017"]


def test_score_caps_repeated_rule():
    steps = "\n".join(f"      - uses: vendor/a{i}@v1" for i in range(10))
    text = "on: push\npermissions: {}\njobs:\n  b:\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    steps:\n" + steps + "\n"
    f = run(text)
    assert len(f) == 10
    assert score(f) == 100 - 3 * 12


def test_lines_point_at_the_real_place():
    # The job ID "deploy" also appears earlier as an input name, and the same expression appears
    # first in a safe env: line. Searching the raw text would blame the wrong lines.
    f = run("""
        on:
          workflow_dispatch:
            inputs:
              deploy:
                type: boolean
        permissions: {}
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - env:
                  BRANCH: ${{ github.head_ref }}
                run: echo "$BRANCH"
              - run: echo "${{ github.head_ref }}"
    """)
    lines = {x.rule_id: x.line for x in f}
    assert lines["GHA009"] == 9    # the job, not the input on line 5
    assert lines["GHA005"] == 15   # the run: line, not the safe env: line 13


def test_issue_comment_bot_checking_out_pr_code_is_a_pwn_request():
    f = run(f"""
        on:
          issue_comment:
            types: [created]
        permissions: {{}}
        jobs:
          test:
            runs-on: ubuntu-latest
            timeout-minutes: 5
            steps:
              - uses: actions/checkout@{SHA}
                with:
                  ref: refs/pull/${{{{ github.event.issue.number }}}}/head
                  persist-credentials: false
    """)
    assert [x.rule_id for x in f] == ["GHA004"]
    assert f[0].line == 13


def test_unsecure_commands_reads_values_not_comments():
    f = run("""
        on: push
        permissions: {}
        # ACTIONS_ALLOW_UNSECURE_COMMANDS: never enable this
        jobs:
          t:
            runs-on: ubuntu-latest
            timeout-minutes: 5
            steps:
              - run: echo
                env:
                  ACTIONS_ALLOW_UNSECURE_COMMANDS: 'true'
    """)
    assert ids(f) == ["GHA013"] and f[0].line == 12


def test_self_hosted_runner_group_on_pr():
    f = run("""
        on: pull_request
        permissions: {}
        jobs:
          b:
            runs-on:
              group: self-hosted-linux
            timeout-minutes: 5
            steps: [{run: make}]
    """)
    assert ids(f) == ["GHA011"]
