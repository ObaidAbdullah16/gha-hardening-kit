# "Were we affected?" - incident exposure checklist

For the question every team asks after a supply-chain incident. `ghaudit exposure` automates steps 1-3; this
list covers the rest. Incident data lives in [`ghaudit/incidents.py`](../ghaudit/incidents.py) with links to the
advisories. Times are UTC.

| Incident | Affected | Window | Safe |
|---|---|---|---|
| CVE-2025-30154 reviewdog | `reviewdog/action-setup@v1` and actions that call it (action-shellcheck, -composite-template, -staticcheck, -ast-grep, -typos) | 11 Mar 2025, 18:42-20:31 | runs outside the window |
| CVE-2025-30066 tj-actions | `tj-actions/changed-files`, every tag up to 45.0.7 (malicious commit `0e58ed86...`) | 14-15 Mar 2025 | 46.0.1 |
| CVE-2026-33634 Trivy (TeamPCP) | `aquasecurity/trivy-action` 0.0.1-0.34.2, `aquasecurity/setup-trivy` 0.2.0-0.2.6, Trivy 0.69.4 | 19-20 Mar 2026 | trivy-action 0.35.0, setup-trivy 0.2.6 (recreated) |
| Checkmarx (TeamPCP) | `checkmarx/ast-github-action`, `checkmarx/kics-github-action`, all tags | 23 Mar 2026, 12:58-19:16; 22 Apr 2026, 14:17-15:41 | ast v2.3.33, kics v2.1.20 |
| Shai-Hulud worms (npm) | workflows planted in repositories: `shai-hulud-workflow.yml` (Sept 2025); `discussion.yaml`, `formatter_*.yml`, runner `SHA1HULUD` (Nov 2025) | Sept and 21-24 Nov 2025 | remove files and runners, rotate |

## Steps

1. **References today.** `ghaudit exposure .` - any affected action still referenced by a tag or a malicious SHA?
2. **References then.** Same command on a full clone: git history shows what the default branch used inside
   each window. Also check long-lived branches that run workflows (`git log --all -- .github/workflows`).
3. **Runs then.** `ghaudit exposure . --repo owner/name` counts workflow runs created in each window (needs a
   token that can read Actions for private repositories).
4. **Read the logs** of those runs for the affected step. For tj-actions and reviewdog, secrets were printed
   into the log (double base64): for public repositories assume anyone could read them. Delete those logs after
   rotating.
5. **Indicators of compromise** in the organisation: repositories named `tpcp-docs` or `docs-tpcp`; repositories
   described "Sha1-Hulud: The Second Coming"; self-hosted runners named `SHA1HULUD`; connections to
   `checkmarx.zone` or `webhook.site` in egress logs.
6. **Rotate** every secret the affected workflows could read - repository, organisation and environment secrets,
   the `GITHUB_TOKEN`'s reach, cloud credentials (prefer replacing keys with OIDC), npm and PyPI tokens - using the
   rotation plan in [secrets-addon.md](secrets-addon.md).
7. **Fix the class of problem:** SHA pins with Dependabot cooldown, `permissions:` blocks, no
   `pull_request_target` checkouts, OIDC, egress monitoring for runners (the main S2 package).

Write the answer down for the client in one paragraph: affected or not, evidence (runs, logs), what was rotated, when.
