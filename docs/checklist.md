# GitHub Actions hardening checklist

Use this list during a client review (service **S2 Pipeline Hardening**). Each item maps to a
`ghaudit` rule so the report and the checklist always agree.

| # | Check | Rule | Why it matters | Fix |
|---|---|---|---|---|
| 1 | Every third-party action pinned to a full commit SHA | GHA001 | Tags can be moved (tj-actions/changed-files 2025, trivy-action 2026) | `python3 tools/pin_actions.py --write .` |
| 2 | Dependabot/Renovate updates the pins, with a cooldown | GHA012 | Pins without updates go stale; cooldown avoids same-day malicious releases | `.github/dependabot.yml` with `cooldown: default-days: 7` |
| 3 | `permissions:` set at the top of every workflow | GHA002 | Default token may have write access to the whole repo | `permissions: {}` then grant per job |
| 4 | No `permissions: write-all` | GHA003 | One compromised step can push code, create releases, change settings | List exact scopes |
| 5 | `pull_request_target`, `workflow_run` and comment bots (`issue_comment`) never check out PR code | GHA004 | "Pwn request": strangers' code runs with secrets | Use `pull_request`; split privileged steps |
| 6 | No `${{ github.event.* }}` text inside `run:` | GHA005 | Script injection via issue titles, PR bodies, branch names | Pass through `env:` |
| 7 | Cloud access through OIDC, not stored keys; the role trusts exact repositories and branches/environments (no wildcards) | GHA006 | Leaked keys work until someone notices; OIDC tokens expire in minutes | `terraform/github-oidc-role` module |
| 8 | No `secrets: inherit` to external workflows | GHA007 | Hands every secret to someone else's code | Pass named secrets only |
| 9 | `persist-credentials: false` on checkout | GHA008 | Token stays in `.git/config` for later steps and uploaded artifacts | Add the input |
| 10 | `timeout-minutes` on every job | GHA009 | Caps cost and abuse (crypto-mining on hijacked runs) | 10-30 minutes is typical |
| 11 | No `curl | sh` | GHA010 | Executes whatever the server returns today | Pin version + verify checksum |
| 12 | No self-hosted runners for pull requests | GHA011 | PR code can persist on a reused machine | GitHub-hosted or ephemeral runners |
| 13 | `ACTIONS_ALLOW_UNSECURE_COMMANDS` not set | GHA013 | Re-enables the set-env injection bug | Use `$GITHUB_ENV` |
| 14 | Secrets passed by `env:`, not inline | GHA014 | Inline secrets are written into the generated script | Use env vars |
| 15 | `workflow_run` artifacts treated as untrusted | GHA015 | Artifact poisoning from fork PR runs | Validate, never execute |
| 16 | Deploy jobs use an `environment:` | GHA016 | Adds approvals and lets the cloud trust policy pin the environment | `environment: production` |
| 17 | Repository setting: default workflow token = read | - | Safer default for new workflows | Settings > Actions > General |
| 18 | Secret scanning + push protection on | - | Stops keys being committed | Settings > Code security |
| 19 | Branch protection / ruleset on `main` | - | Workflow changes get reviewed | Settings > Rules |
| 20 | `zizmor` and `actionlint` in CI | - | Keeps it fixed after you leave | See `.github/workflows/ci.yml` |

## Secrets-exposure add-on (+half a day)

| # | Check | Tool | Fix |
|---|---|---|---|
| 21 | No secret anywhere in git history (all branches and tags) | `tools/secrets-history-scan.sh` | Rotate in plan order; history rewrite optional, after rotation |
| 22 | Not exposed to a known Actions incident (references, history, runs in the windows) | `ghaudit exposure . --repo org/repo` | Pin to safe SHAs; rotate what affected runs could read |
| 23 | No Shai-Hulud workflows or `SHA1HULUD` runners; no `tpcp-docs` repositories | `ghaudit exposure`; org audit log | Remove, rotate, review audit log |
| 24 | Every exposed secret has an owner, a rotation date and a confirmed revoke | `rotation-plan.csv` | Fill it in with the client |

See [secrets-addon.md](secrets-addon.md) and [incident-exposure-checklist.md](incident-exposure-checklist.md).

## How I deliver the service (2-3 days)

1. **Free 15-minute review** (public repo): `ghaudit scan --repo client/repo --format md`. Send the score and top 3 findings.
2. **Engagement**: client adds me as a collaborator with *write* access to one repo (no org admin, no cloud access).
3. **One pull request** with: pinned actions, `permissions:` blocks, injection fixes, Dependabot config, timeouts.
4. **OIDC migration**: Terraform module + a second PR switching the deploy job to `role-to-assume`. Client deletes the old access keys (I never see them).
5. **Report**: before/after HTML report (`ghaudit compare`) + this checklist with every row ticked or explained.
6. **Secrets add-on (if bought)**: history scan on a fresh mirror clone, `ghaudit exposure` with `--repo`, rotation plan
   filled in with the client on a call, push protection turned on by the client.
