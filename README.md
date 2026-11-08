# gha-hardening-kit

[![CI](https://github.com/ObaidAbdullah16/gha-hardening-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/ObaidAbdullah16/gha-hardening-kit/actions/workflows/ci.yml)
[![Hardening report](https://github.com/ObaidAbdullah16/gha-hardening-kit/actions/workflows/audit-report.yml/badge.svg)](https://obaidabdullah16.github.io/gha-hardening-kit/)

> **Demo repository.** The workflows in `examples/before/` are *deliberately insecure* and never run
> (they are not in `.github/workflows`). Everything in `.github/workflows/` is real and hardened.

Toolkit behind my **GitHub Actions Pipeline Hardening** service (S2). After the 2025-26 supply-chain
incidents (tj-actions/changed-files, the trivy-action tag hijack, compromised CI secrets), most teams
still use mutable tags, write-all tokens and long-lived cloud keys. This kit finds and fixes that.

| Part | What it does |
|---|---|
| [`ghaudit/`](ghaudit) | Python CLI that scores a repo's workflows 0-100 with 16 rules; outputs text, Markdown, JSON, **SARIF** (GitHub Security tab) and an HTML before/after report |
| [`tools/pin_actions.py`](tools/pin_actions.py) | Pins every `uses:` to a full commit SHA (`@<sha> # v7`). Standard library only |
| [`terraform/github-oidc-role`](terraform/github-oidc-role) | Terraform module: GitHub OIDC provider + a role only `main`/an environment can assume. Refuses wildcard repositories and subjects |
| [`examples/before` → `examples/after`](examples) | Five realistic workflows, before and after hardening |
| [`.github/workflows/reusable-python-ci.yml`](.github/workflows/reusable-python-ci.yml) | Hardened reusable CI job clients can call |
| [`docs/checklist.md`](docs/checklist.md) | 20-point client checklist and how the service is delivered |
| `ghaudit exposure` | "Were we affected?": checks today's workflows, the **git history inside each incident window** and (with `--repo`) the **workflow runs** in those windows against tj-actions, reviewdog, Trivy and Checkmarx compromises, plus Shai-Hulud worm workflows |
| [`tools/secrets-history-scan.sh`](tools/secrets-history-scan.sh) + `ghaudit secrets-plan` | Secrets-exposure add-on: full-history scan on a fresh mirror clone (gitleaks, TruffleHog **without verification**) turned into a rotation plan that never contains a secret value |
| [`docs/secrets-addon.md`](docs/secrets-addon.md), [`docs/incident-exposure-checklist.md`](docs/incident-exposure-checklist.md) | Procedure, the "verify without using" rule, rotation order, incident windows and indicators of compromise |

## Live demo (free, on GitHub)

- **Before/after report:** https://obaidabdullah16.github.io/gha-hardening-kit/ (rebuilt by CI on every push)
- **Self-audit:** the `CI` workflow runs `actionlint`, `zizmor`, `gitleaks`, the SHA-pin check and `ghaudit --fail-under 90` on this repo. Results appear in the Security tab as SARIF.
- **Start / stop the report site:** `bash scripts/up.sh` turns GitHub Pages on and publishes the report;
  `bash scripts/down.sh` takes it offline (free either way); `bash scripts/status.sh` shows where it is.
- **OIDC demo:** Actions > *AWS OIDC demo* > Run workflow. It logs in to AWS with no stored keys, using a role with **zero permissions**, and shows that anything else is denied.

## Quick start

```bash
pip install -e ".[dev]"
ghaudit rules                                   # list the 16 rules
ghaudit scan .                                  # this repo
ghaudit scan --repo some-org/some-repo          # any public repo (export GH_TOKEN=$(gh auth token) for higher limits)
ghaudit scan . --format sarif -o ghaudit.sarif  # upload with github/codeql-action/upload-sarif
ghaudit compare --before examples/before/workflows --after examples/after/workflows --html report.html

GH_TOKEN=$(gh auth token) python3 tools/pin_actions.py --write .   # pin everything
python3 tools/pin_actions.py --check .                             # CI gate
ghaudit exposure . --repo some-org/some-repo                       # known incidents: references, history, runs in the windows
bash tools/secrets-history-scan.sh https://github.com/org/app.git out/app   # history scan -> rotation-plan.csv
bash tools/make-secrets-demo-repo.sh /tmp/acme-app                 # local practice repo with fake secrets in history
pytest -q                                                          # 49 tests
```

## Rules

| ID | Severity | Rule |
|---|---|---|
| GHA001 | high (3rd party) / medium (actions/*) | Action not pinned to a commit SHA |
| GHA002 | medium | No `permissions:` block |
| GHA003 | high | `permissions: write-all` |
| GHA004 | critical | `pull_request_target` / `workflow_run` / `issue_comment` checks out PR code ("pwn request") |
| GHA005 | high | Untrusted `${{ github.event.* }}` in `run:` or `github-script` |
| GHA006 | high | Long-lived cloud keys instead of OIDC |
| GHA007 | medium | `secrets: inherit` to a reusable workflow |
| GHA008 | low | `actions/checkout` keeps credentials |
| GHA009 | low | No `timeout-minutes` |
| GHA010 | medium | `curl … \| sh` |
| GHA011 | high | Self-hosted runner on pull requests |
| GHA012 | medium | No Dependabot/Renovate for actions |
| GHA013 | high | `ACTIONS_ALLOW_UNSECURE_COMMANDS` |
| GHA014 | medium | Secret expanded inline in a script |
| GHA015 | medium | `workflow_run` artifact download (poisoning) |
| GHA016 | low | Cloud role assumed without an `environment:` |

**Scoring:** start at 100, subtract 25/12/6/2 for critical/high/medium/low, at most 3 hits per rule per file.
Grades: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F < 40. The shipped examples score **0/100 (F)** before and
**100/100 (A)** after pinning.

## Secrets-exposure add-on

After the 2025-26 incidents the next question is always *"were we affected, and what do we rotate?"*
`ghaudit exposure` answers the first from evidence the repository already has: a tag reference today is a
risk, a tag reference **inside an incident window** on the default branch (git history) is exposure, and a
**workflow run** in that window (GitHub API) is the moment to rotate. Incident data with advisory links lives in
[`ghaudit/incidents.py`](ghaudit/incidents.py).

The history scan never tests a found credential by using it (TruffleHog runs with `--no-verification`; AWS key
IDs can be looked up with `aws sts get-access-key-info` using *your* credentials) and never writes a secret value:
the rotation plan holds type, file, line, commit and date only. The kit runs the exposure check on itself in CI.

## How it relates to zizmor and actionlint

`ghaudit` is not a replacement for [zizmor](https://docs.zizmor.sh) (deep static analysis) or
[actionlint](https://github.com/rhysd/actionlint) (syntax/type checks); this repo's CI runs both.
`ghaudit` adds what a *client report* needs: one score, a grade, plain-English fixes, a before/after
comparison, and repo-level checks (Dependabot coverage).

## Design notes (for interviews)

- **YAML 1.1 gotcha:** PyYAML parses the key `on:` as boolean `True`; the loader normalises it.
- **Line numbers** come from PyYAML's node marks (`yaml.compose`), not a text search, so SARIF alerts land on the exact key even when the same text appears earlier in the file.
- **`--min-severity`** only hides findings from the output; the score and `--fail-under` always count everything.
- **Pinning** uses the GitHub API's `application/vnd.github.sha` media type, so resolving a tag is one cheap request and annotated tags resolve to the commit.
- **`self-repository` (`uses: $/...`)**, the new GitHub syntax from July 2026, is not yet supported by actionlint 1.7.12, so `.github/zizmor.yml` documents a narrow ignore instead of disabling the audit.

MIT licensed.
