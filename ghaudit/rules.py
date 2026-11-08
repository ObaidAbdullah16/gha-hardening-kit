"""The audit rules. Each rule is a small, readable function.

Rule IDs are stable (GHA001...) so reports and SARIF alerts stay comparable over time.
References point to GitHub's own security hardening guide.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from typing import Any

from .model import Finding, RepoContext, Rule, WorkflowFile

GUIDE = "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions"

RULES: dict[str, Rule] = {
    r.id: r
    for r in [
        Rule("GHA001", "unpinned-action", "high",
             "Action referenced by a tag or branch instead of a full commit SHA.",
             "Pin to a 40-character commit SHA and keep the tag as a comment (tools/pin_actions.py does this). "
             "Let Dependabot or Renovate update the pins.", GUIDE),
        Rule("GHA002", "missing-permissions", "medium",
             "No `permissions:` block, so the GITHUB_TOKEN gets the repository default (often read/write).",
             "Add `permissions: {}` (or `contents: read`) at the top of the workflow and grant extra scopes per job.", GUIDE),
        Rule("GHA003", "write-all-permissions", "high",
             "`permissions: write-all` gives the token write access to everything.",
             "List only the scopes the job needs, e.g. `contents: read`, `id-token: write`.", GUIDE),
        Rule("GHA004", "pwn-request", "critical",
             "`pull_request_target`/`workflow_run` workflow checks out and runs untrusted pull-request code with secrets available.",
             "Use `pull_request` for building PR code. If you must use `pull_request_target`, never check out the PR head, "
             "or split into an unprivileged build and a privileged comment step.",
             "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/"),
        Rule("GHA005", "script-injection", "high",
             "Attacker-controlled text (issue title, PR body, branch name...) is expanded directly inside a `run:` script.",
             "Pass the value through an environment variable: `env: TITLE: ${{ github.event.issue.title }}` and use \"$TITLE\".", GUIDE),
        Rule("GHA006", "long-lived-cloud-credentials", "high",
             "Static cloud keys from secrets are used instead of OIDC.",
             "Use OpenID Connect: `aws-actions/configure-aws-credentials` with `role-to-assume` and `permissions: id-token: write`.",
             "https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect"),
        Rule("GHA007", "secrets-inherit", "medium",
             "`secrets: inherit` passes every repository secret to a reusable workflow.",
             "Pass only the secrets the called workflow needs.", GUIDE),
        Rule("GHA008", "checkout-persists-credentials", "low",
             "`actions/checkout` leaves the token in .git/config for later steps (and any artifact that uploads the workspace).",
             "Add `with: persist-credentials: false` unless a later step really needs to push.", GUIDE),
        Rule("GHA009", "missing-timeout", "low",
             "Job has no `timeout-minutes` (default is 360 minutes).",
             "Set `timeout-minutes` on every job to cap runaway or abused runs.", ""),
        Rule("GHA010", "curl-pipe-shell", "medium",
             "A script is downloaded and executed in one step (`curl ... | sh`).",
             "Download a pinned version, verify its checksum or signature, then run it - or use a pinned action.", ""),
        Rule("GHA011", "self-hosted-runner-on-pr", "high",
             "Self-hosted runner used by a workflow that runs on pull requests.",
             "Use GitHub-hosted runners for untrusted code, or ephemeral, isolated self-hosted runners.", GUIDE),
        Rule("GHA012", "no-action-updates", "medium",
             "No Dependabot or Renovate configuration keeps GitHub Actions up to date.",
             "Add `.github/dependabot.yml` with `package-ecosystem: github-actions`.", ""),
        Rule("GHA013", "unsecure-commands", "high",
             "`ACTIONS_ALLOW_UNSECURE_COMMANDS` re-enables the deprecated set-env/add-path commands (CVE-2020-15228).",
             "Remove it and write to $GITHUB_ENV / $GITHUB_PATH instead.", GUIDE),
        Rule("GHA014", "inline-secret-in-script", "medium",
             "A secret is expanded directly inside a `run:` script.",
             "Pass secrets through `env:` and reference \"$NAME\" so they are not written into the generated script.", GUIDE),
        Rule("GHA015", "artifact-poisoning", "medium",
             "A `workflow_run` workflow downloads artifacts produced by a possibly untrusted run.",
             "Treat downloaded artifacts as untrusted data: never execute them, validate content, extract to a temp dir.",
             "https://securitylab.github.com/resources/github-actions-new-patterns-and-mitigations/"),
        Rule("GHA016", "deploy-without-environment", "low",
             "A job assumes a cloud role but has no `environment:` (no approval gate, broader OIDC subject).",
             "Add `environment: <name>` and restrict the cloud role's trust policy to that environment.", ""),
        Rule("GHA017", "parse-error", "info",
             "The workflow file could not be parsed as YAML.",
             "Fix the YAML syntax (actionlint gives precise errors).", ""),
    ]
}

FIRST_PARTY_OWNERS = {"actions", "github"}

# Contexts an outside contributor can control (from GitHub's hardening guide).
UNTRUSTED_CONTEXT = re.compile(
    r"\$\{\{\s*("
    r"github\.event\.(issue|pull_request|discussion)\.(title|body)"
    r"|github\.event\.(comment|review|review_comment)\.body"
    r"|github\.event\.pages\.[^}]*\.page_name"
    r"|github\.event\.(head_commit|commits[^}]*)\.(message|author\.(email|name))"
    r"|github\.event\.pull_request\.head\.(ref|label|repo\.default_branch)"
    r"|github\.event\.workflow_run\.(head_branch|head_commit\.message|display_title)"
    r"|github\.head_ref"
    r")[^}]*\}\}"
)
SECRET_EXPR = re.compile(r"\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}")
CURL_PIPE = re.compile(r"(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z)?sh\b")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
STATIC_KEY_NAMES = {
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AZURE_CREDENTIALS", "GOOGLE_CREDENTIALS",
    "GCP_SA_KEY", "GOOGLE_APPLICATION_CREDENTIALS_JSON",
}

Check = Callable[[WorkflowFile, RepoContext], Iterable[Finding]]


# --------------------------------------------------------------------------- helpers
def triggers(wf: WorkflowFile) -> set[str]:
    on = wf.data.get("on")
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(x) for x in on}
    if isinstance(on, dict):
        return {str(k) for k in on}
    return set()


def jobs(wf: WorkflowFile) -> dict[str, dict[str, Any]]:
    j = wf.data.get("jobs")
    return {k: v for k, v in j.items() if isinstance(v, dict)} if isinstance(j, dict) else {}


def steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    s = job.get("steps")
    return [x for x in s if isinstance(x, dict)] if isinstance(s, list) else []


def step_label(step: dict[str, Any], idx: int) -> str:
    return str(step.get("name") or step.get("uses") or step.get("id") or f"step {idx + 1}")


def mk(rule_id: str, wf: WorkflowFile, line: int, msg: str, job: str = "", step: str = "", severity: str | None = None) -> Finding:
    return Finding(rule_id=rule_id, severity=severity or RULES[rule_id].severity, file=wf.path,
                   line=line, message=msg, job=job, step=step)


def job_line(wf: WorkflowFile, job_id: str) -> int:
    return wf.line_of("jobs", job_id, default=wf.find_line(f"{job_id}:"))


def regex_line(wf: WorkflowFile, rx: re.Pattern[str], start: int = 1) -> int:
    for i, ln in enumerate(wf.lines[start - 1 :], start=start):
        if rx.search(ln):
            return i
    return start


# --------------------------------------------------------------------------- rules
def check_unpinned(wf: WorkflowFile, ctx: RepoContext) -> Iterable[Finding]:
    for job_id, job in jobs(wf).items():
        refs = []
        if isinstance(job.get("uses"), str):
            refs.append((job["uses"], "", wf.line_of("jobs", job_id, "uses")))
        for i, st in enumerate(steps(job)):
            if isinstance(st.get("uses"), str):
                refs.append((st["uses"], step_label(st, i), wf.line_of("jobs", job_id, "steps", i, "uses")))
        for ref, label, line in refs:
            if ref.startswith("./"):
                continue
            if ref.startswith("docker://"):
                if "@sha256:" not in ref:
                    yield mk("GHA001", wf, line, f"Container image `{ref}` is not pinned by digest.", job_id, label, "medium")
                continue
            if "@" not in ref:
                yield mk("GHA001", wf, line, f"`{ref}` has no version at all.", job_id, label)
                continue
            target, version = ref.rsplit("@", 1)
            if SHA_RE.match(version):
                continue
            owner = target.split("/")[0].lower()
            sev = "medium" if owner in FIRST_PARTY_OWNERS else "high"
            yield mk("GHA001", wf, line, f"`{ref}` uses a mutable reference `{version}`.", job_id, label, sev)


def _perm_is_write_all(p: Any) -> bool:
    return isinstance(p, str) and p.strip() == "write-all"


def check_permissions(wf: WorkflowFile, ctx: RepoContext) -> Iterable[Finding]:
    top = wf.data.get("permissions", None)
    all_jobs = jobs(wf)
    if _perm_is_write_all(top):
        yield mk("GHA003", wf, wf.line_of("permissions"), "Workflow-level `permissions: write-all`.")
    if top is None:
        missing = [j for j, v in all_jobs.items() if "permissions" not in v]
        if missing:
            yield mk("GHA002", wf, 1, f"No top-level `permissions:` and {len(missing)} job(s) without their own: {', '.join(missing)}.")
    for job_id, job in all_jobs.items():
        if _perm_is_write_all(job.get("permissions")):
            yield mk("GHA003", wf, wf.line_of("jobs", job_id, "permissions"), f"Job `{job_id}` uses `permissions: write-all`.", job_id)


def check_pwn_request(wf: WorkflowFile, ctx: RepoContext) -> Iterable[Finding]:
    # These triggers run with the base repository's secrets and a write token, even for a fork's PR.
    risky = triggers(wf) & {"pull_request_target", "workflow_run", "issue_comment"}
    if not risky:
        return
    for job_id, job in jobs(wf).items():
        for i, st in enumerate(steps(job)):
            uses = str(st.get("uses", ""))
            with_ = st.get("with") or {}
            ref = str(with_.get("ref", "")) if isinstance(with_, dict) else ""
            if uses.startswith("actions/checkout") and re.search(
                r"github\.event\.pull_request\.head|github\.head_ref|refs/pull/|github\.event\.workflow_run\.head"
                r"|steps\.[\w-]+\.outputs\.head_(sha|ref)", ref  # e.g. a "get PR branch" step in comment bots
            ):
                yield mk("GHA004", wf, wf.line_of("jobs", job_id, "steps", i, "with", "ref"),
                         f"`{', '.join(sorted(risky))}` job `{job_id}` checks out untrusted PR code (`ref: {ref}`).",
                         job_id, step_label(st, i))


def check_script_injection(wf: WorkflowFile, ctx: RepoContext) -> Iterable[Finding]:
    for job_id, job in jobs(wf).items():
        for i, st in enumerate(steps(job)):
            scripts = []  # (script text, line where it starts)
            if isinstance(st.get("run"), str):
                scripts.append((st["run"], wf.line_of("jobs", job_id, "steps", i, "run")))
            with_ = st.get("with") if isinstance(st.get("with"), dict) else {}
            if str(st.get("uses", "")).startswith("actions/github-script") and isinstance(with_.get("script"), str):
                scripts.append((with_["script"], wf.line_of("jobs", job_id, "steps", i, "with", "script")))
            for script, start in scripts:
                # Search from where *this* script starts, so a safe copy of the same expression in an
                # earlier `env:` line or step is never blamed.
                for m in UNTRUSTED_CONTEXT.finditer(script):
                    yield mk("GHA005", wf, wf.find_line(m.group(0), start),
                             f"`{m.group(0)}` is expanded inside a script.", job_id, step_label(st, i))
                for m in SECRET_EXPR.finditer(script):
                    yield mk("GHA014", wf, wf.find_line(m.group(0), start),
                             f"`{m.group(0)}` is expanded inside a script.", job_id, step_label(st, i))
                if CURL_PIPE.search(script):
                    yield mk("GHA010", wf, regex_line(wf, CURL_PIPE, start),
                             "Remote script piped straight into a shell.", job_id, step_label(st, i))


def _env_static_keys(env: Any) -> list[str]:
    if not isinstance(env, dict):
        return []
    return [k for k, v in env.items() if k in STATIC_KEY_NAMES and "secrets." in str(v)]


def check_static_credentials(wf: WorkflowFile, ctx: RepoContext) -> Iterable[Finding]:
    for k in _env_static_keys(wf.data.get("env")):
        yield mk("GHA006", wf, wf.line_of("env", k), f"Workflow env `{k}` comes from a long-lived secret.")
    for job_id, job in jobs(wf).items():
        for k in _env_static_keys(job.get("env")):
            yield mk("GHA006", wf, wf.line_of("jobs", job_id, "env", k), f"Job env `{k}` comes from a long-lived secret.", job_id)
        for i, st in enumerate(steps(job)):
            for k in _env_static_keys(st.get("env")):
                yield mk("GHA006", wf, wf.line_of("jobs", job_id, "steps", i, "env", k),
                         f"Step env `{k}` comes from a long-lived secret.", job_id, step_label(st, i))
            with_ = st.get("with") if isinstance(st.get("with"), dict) else {}
            for key in ("aws-access-key-id", "aws-secret-access-key", "creds", "credentials_json"):
                if key in with_ and "secrets." in str(with_[key]):
                    yield mk("GHA006", wf, wf.line_of("jobs", job_id, "steps", i, "with", key),
                             f"Input `{key}` is a long-lived secret.", job_id, step_label(st, i))


def check_secrets_inherit(wf: WorkflowFile, ctx: RepoContext) -> Iterable[Finding]:
    for job_id, job in jobs(wf).items():
        if job.get("secrets") == "inherit" and isinstance(job.get("uses"), str):
            sev = "low" if job["uses"].startswith("./") else "medium"
            yield mk("GHA007", wf, wf.line_of("jobs", job_id, "secrets"), f"Job `{job_id}` passes all secrets to `{job['uses']}`.",
                     job_id, severity=sev)


def check_checkout_credentials(wf: WorkflowFile, ctx: RepoContext) -> Iterable[Finding]:
    for job_id, job in jobs(wf).items():
        for i, st in enumerate(steps(job)):
            uses = str(st.get("uses", ""))
            if not uses.startswith("actions/checkout"):
                continue
            line = wf.line_of("jobs", job_id, "steps", i, "uses")
            with_ = st.get("with") if isinstance(st.get("with"), dict) else {}
            if str(with_.get("persist-credentials", "true")).lower() != "false":
                yield mk("GHA008", wf, line, "Checkout keeps the token in .git/config.", job_id, step_label(st, i))


def check_timeouts(wf: WorkflowFile, ctx: RepoContext) -> Iterable[Finding]:
    for job_id, job in jobs(wf).items():
        if "uses" in job:  # reusable workflow call: timeout is set inside the callee
            continue
        if "timeout-minutes" not in job:
            yield mk("GHA009", wf, job_line(wf, job_id), f"Job `{job_id}` has no timeout-minutes.", job_id)


def check_self_hosted(wf: WorkflowFile, ctx: RepoContext) -> Iterable[Finding]:
    if not triggers(wf) & {"pull_request", "pull_request_target", "issue_comment"}:
        return
    for job_id, job in jobs(wf).items():
        runs_on = job.get("runs-on")
        if isinstance(runs_on, dict):  # runs-on: {group: ..., labels: [...]}
            labels = [runs_on.get("group")] + (runs_on.get("labels") if isinstance(runs_on.get("labels"), list) else [runs_on.get("labels")])
        else:
            labels = runs_on if isinstance(runs_on, list) else [runs_on]
        if any(isinstance(x, str) and "self-hosted" in x for x in labels):
            yield mk("GHA011", wf, job_line(wf, job_id), f"Job `{job_id}` runs pull-request code on a self-hosted runner.", job_id)


def check_unsecure_commands(wf: WorkflowFile, ctx: RepoContext) -> Iterable[Finding]:
    key = "ACTIONS_ALLOW_UNSECURE_COMMANDS"
    places: list[tuple[Any, tuple[Any, ...], str]] = [(wf.data.get("env"), ("env",), "")]
    for job_id, job in jobs(wf).items():
        places.append((job.get("env"), ("jobs", job_id, "env"), job_id))
        for i, st in enumerate(steps(job)):
            places.append((st.get("env"), ("jobs", job_id, "steps", i, "env"), job_id))
    for env, path, job_id in places:
        # Read the parsed value (a comment mentioning the name must not hide or trigger anything).
        if isinstance(env, dict) and str(env.get(key, "")).strip().lower() == "true":
            yield mk("GHA013", wf, wf.line_of(*path, key), f"{key} is enabled.", job_id)


def check_artifact_poisoning(wf: WorkflowFile, ctx: RepoContext) -> Iterable[Finding]:
    if "workflow_run" not in triggers(wf):
        return
    for job_id, job in jobs(wf).items():
        for i, st in enumerate(steps(job)):
            uses = str(st.get("uses", ""))
            with_ = st.get("with") if isinstance(st.get("with"), dict) else {}
            if uses.startswith("dawidd6/action-download-artifact") or (
                uses.startswith("actions/download-artifact") and "run-id" in with_
            ):
                yield mk("GHA015", wf, wf.line_of("jobs", job_id, "steps", i, "uses"),
                         "Artifacts from another workflow run are downloaded.", job_id, step_label(st, i))


def check_deploy_environment(wf: WorkflowFile, ctx: RepoContext) -> Iterable[Finding]:
    for job_id, job in jobs(wf).items():
        if "environment" in job:
            continue
        for i, st in enumerate(steps(job)):
            uses = str(st.get("uses", ""))
            with_ = st.get("with") if isinstance(st.get("with"), dict) else {}
            if uses.startswith(("aws-actions/configure-aws-credentials", "azure/login", "google-github-actions/auth")) and (
                "role-to-assume" in with_ or "client-id" in with_ or "workload_identity_provider" in with_
            ):
                yield mk("GHA016", wf, job_line(wf, job_id), f"Job `{job_id}` assumes a cloud role without an environment.", job_id, step_label(st, i))
                break


WORKFLOW_CHECKS: list[Check] = [
    check_unpinned,
    check_permissions,
    check_pwn_request,
    check_script_injection,
    check_static_credentials,
    check_secrets_inherit,
    check_checkout_credentials,
    check_timeouts,
    check_self_hosted,
    check_unsecure_commands,
    check_artifact_poisoning,
    check_deploy_environment,
]


def audit(ctx: RepoContext) -> list[Finding]:
    findings: list[Finding] = []
    for wf in ctx.workflows:
        if wf.parse_error:
            findings.append(mk("GHA017", wf, 1, wf.parse_error))
            continue
        for check in WORKFLOW_CHECKS:
            findings.extend(check(wf, ctx))
    if ctx.workflows and not (ctx.has_dependabot_actions or ctx.has_renovate):
        findings.append(Finding("GHA012", RULES["GHA012"].severity, ".github/dependabot.yml", 1,
                                "Nothing updates pinned actions; pins will go stale."))
    findings.sort(key=lambda f: (f.file, f.line, f.rule_id))
    return findings
