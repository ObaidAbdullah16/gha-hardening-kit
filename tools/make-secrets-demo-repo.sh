#!/usr/bin/env bash
# Build a LOCAL demo repository for the secrets-exposure add-on video and practice:
# fake secrets committed in the past and later "deleted", and a workflow that used
# tj-actions/changed-files by tag during the March 2025 incident window.
#
#   bash tools/make-secrets-demo-repo.sh /tmp/acme-app
#   bash tools/secrets-history-scan.sh /tmp/acme-app audits/demo/secrets
#   ghaudit exposure /tmp/acme-app
#
# Every value is fake and says so. The repository is never pushed anywhere: keep it that way, because
# real scanners (GitHub, AWS) would raise alarms about anything that looks like a key in a public repo.
set -euo pipefail
DIR="${1:?usage: make-secrets-demo-repo.sh <new-empty-folder>}"
[ ! -e "$DIR" ] || [ -z "$(ls -A "$DIR")" ] || { echo "$DIR is not empty" >&2; exit 1; }
mkdir -p "$DIR/.github/workflows"
cd "$DIR"
git init -q -b main
git config user.name "Demo Developer"
git config user.email "dev@example.com"
commit() { GIT_AUTHOR_DATE="$1" GIT_COMMITTER_DATE="$1" git commit -q -m "$2"; }

cat > .github/workflows/ci.yml <<'YML'
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: tj-actions/changed-files@v44
      - run: npm test
YML
cat > .env <<'ENV'
# DEMO ONLY - fake values for a training repository
AWS_ACCESS_KEY_ID=AKIAQZ4DEMONOTREAL7X
DB_URL=postgres://app:demo-not-a-real-password@db.internal:5432/app
ENV
git add -A && commit "2025-01-10T10:00:00Z" "initial app and CI"

cat > notify.py <<'PY'
# DEMO ONLY - fake webhook for a training repository
SLACK_WEBHOOK = "https://hooks.slack.com/services/T0DEMO0000/B0DEMO0000/demoNotARealWebhookToken00"
PY
git add -A && commit "2025-02-01T09:30:00Z" "slack notifications"

git rm -q .env
sed -i 's|tj-actions/changed-files@v44|tj-actions/changed-files@0123456789abcdef0123456789abcdef01234567 # demo pin, not a real commit|' .github/workflows/ci.yml
git add -A && commit "2025-03-20T16:00:00Z" "remove .env, pin changed-files"
echo "Demo repository ready in $DIR ($(git rev-list --count HEAD) commits). The secrets are gone from the latest code, not from history."
