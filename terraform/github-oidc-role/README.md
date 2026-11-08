# Module: github-oidc-role

Creates (or reuses) the GitHub Actions OIDC provider and one IAM role that only the
workflow runs you list can assume. Replaces long-lived `AWS_ACCESS_KEY_ID` secrets.

```hcl
module "deploy_role" {
  source             = "github.com/ObaidAbdullah16/gha-hardening-kit//terraform/github-oidc-role"
  role_name          = "github-deploy"
  repositories       = ["acme/web"]
  subjects           = ["environment:production"]   # or "ref:refs/heads/main"
  inline_policy_json = data.aws_iam_policy_document.least_privilege.json
}
```

Workflow side:

```yaml
permissions:
  id-token: write
  contents: read
jobs:
  deploy:
    environment: production
    steps:
      - uses: aws-actions/configure-aws-credentials@<sha> # v6
        with:
          role-to-assume: ${{ vars.AWS_ROLE_ARN }}
          aws-region: ap-south-1
```

Validation refuses the most common OIDC trust mistakes before anything is created:

- `repositories` must be exact `owner/name` values. A wildcard owner (`*/*`, `repo:*`) would let
  workflows in *any* GitHub repository assume the role.
- `subjects` must name a branch (`ref:refs/heads/main`), a tag (`ref:refs/tags/v*`) or an environment
  (`environment:production`) and start with a literal character. `*`, `ref:*`,
  `ref:refs/heads/*` (any branch, so anyone who can push a branch), `environment:*` and
  `pull_request` are refused.
