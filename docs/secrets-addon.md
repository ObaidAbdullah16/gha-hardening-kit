# Secrets-exposure add-on (service S2)

Sold with any S2 package: **+$75 founding / +$150 standard / +₹4k**, half a day to a day.
The question it answers: *"Which credentials have ever been committed or exposed by our pipelines, and in
what order do we rotate them?"*

| Step | Tool | Output |
|---|---|---|
| 1. History scan | `tools/secrets-history-scan.sh` (gitleaks, plus TruffleHog **without verification** if installed) | `summary.md`, `rotation-plan.csv` |
| 2. Incident exposure | `ghaudit exposure <checkout> --repo owner/name` | which known incidents touched the repo, and whether workflows ran in the windows |
| 3. Rotation plan | the CSV, filled in with the client | owner, systems, blast radius, order |
| 4. Prevention | push protection, `gitleaks` in CI, OIDC instead of keys | settings changed by the client; PR from you |

## 1. History scan - on a fresh clone, never on their systems

```bash
bash tools/secrets-history-scan.sh https://github.com/client/app.git audits/client-app/secrets
```

- The script makes a **mirror clone** (every branch and tag) in a temporary folder, runs gitleaks with
  `--redact`, optionally TruffleHog with `--no-verification`, writes the plan, and deletes the clone.
- Deleting a commit does not remove a secret: forks, clones, CI caches and GitHub's own caches keep it. A
  committed secret is rotated, not "cleaned".
- Rewriting history (git filter-repo) is optional and only *after* rotation, to stop scanners re-reporting it.

### Practise first (and for the demo video)

```bash
bash tools/make-secrets-demo-repo.sh /tmp/acme-app          # local repo, fake secrets in history, never pushed
bash tools/secrets-history-scan.sh /tmp/acme-app audits/demo/secrets
ghaudit exposure /tmp/acme-app                             # the workflow used tj-actions/changed-files@v44 in March 2025
```

## 2. The "verify without using" rule

We never find out whether a credential works by **using** it. That is unauthorised access even when the
key was committed by mistake, and it is how a review turns into an incident. Instead:

| Credential | Safe way to learn something | Never |
|---|---|---|
| AWS access key ID (`AKIA...`) | `aws sts get-access-key-info --access-key-id AKIA...` with **your own** credentials: returns the owning account ID, never uses the secret | `aws ... --profile leaked` |
| Anything else (GitHub, Stripe, database, SMTP, Slack...) | Ask the owner to check it in the provider's console (last used, status) | calling the provider's API with it |
| TruffleHog | `--no-verification` (verification calls the provider with the found key) | default verification mode |

Report every finding by **type, file, line, commit and date** - never the value, not even partly masked in
screenshots.

## 3. Rotation plan

Fill the CSV with the client on a call:

1. **Owner** - who can rotate it; **used by** - every system that reads it (apps, CI, cron jobs, laptops).
2. **Blast radius** - what an attacker could do with it (read data, spend money, push code, send email).
3. **Order** - the plan pre-sorts: 1 today (cloud, CI/CD, source control, payments), 2 this week (databases,
   email providers), 3 next. A secret found next to a cloud key in the same commit inherits its urgency.
4. For each: create the new credential, deploy it everywhere, confirm the service works, **then** revoke the old
   one, and write down the dates. Skipping "confirm" is how rotations cause outages.
5. Where possible replace the secret instead of rotating it: OIDC roles for CI (`terraform/github-oidc-role`),
   IAM roles for workloads, short-lived tokens.

Template columns: `#, rotate, secret type, detected by, file, line, commit, committed on, committed by,
still in latest code?, owner, used by, blast radius, rotated on, old one revoked on, owner confirmed working`.

## 4. Prevention (so the plan stays short)

- Settings > Code security: **secret scanning + push protection** (free for public repositories; GitHub Secret
  Protection for private ones). The client clicks; you send the steps.
- `gitleaks` in CI (this repository's `CI` workflow shows the job).
- Dependabot with a cooldown, SHA pins and OIDC from the main S2 package.

## Data handling

Scanner reports contain locations, not values, but they are still sensitive: keep them in the engagement folder
(`audits/` is git-ignored), delete them after the agreed retention, and confirm deletion in writing.
