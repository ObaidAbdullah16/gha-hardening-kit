#!/usr/bin/env bash
# Secrets-exposure add-on (service S2): scan a repository's FULL git history for committed secrets
# and produce a rotation plan - without ever printing or testing a secret value.
#
#   bash tools/secrets-history-scan.sh https://github.com/client/app.git  out/client-app
#   bash tools/secrets-history-scan.sh /path/to/local/checkout            out/local
#
# Rules: work on a fresh mirror clone in a temporary folder (never on the client's systems), keep values
# redacted, never verify a secret by using it, delete the clone at the end.
set -euo pipefail

SRC="${1:?usage: secrets-history-scan.sh <git-url-or-path> <output-dir>}"
OUT="${2:?usage: secrets-history-scan.sh <git-url-or-path> <output-dir>}"
NAME="$(basename "${SRC%.git}")"
command -v gitleaks >/dev/null || { echo "gitleaks is required: https://github.com/gitleaks/gitleaks#installing" >&2; exit 1; }
command -v ghaudit >/dev/null || { echo "ghaudit is required: pip install -e . (in gha-hardening-kit)" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"
chmod 700 "$OUT"

echo "Cloning a fresh mirror (all branches and tags) into a temporary folder..."
git clone --quiet --mirror "$SRC" "$WORK/repo.git"

echo "gitleaks: scanning every commit (values redacted)..."
gitleaks git "$WORK/repo.git" --redact --no-banner --exit-code 0 \
  --report-format json --report-path "$OUT/gitleaks.json" >/dev/null 2>&1

ARGS=(--gitleaks "$OUT/gitleaks.json")
if command -v trufflehog >/dev/null; then
  echo "TruffleHog: second opinion, WITHOUT verification (it never calls the provider with a found key)..."
  trufflehog git "file://$WORK/repo.git" --no-verification --json 2>/dev/null \
    | python3 -c 'import json,sys
for line in sys.stdin:
    try: d = json.loads(line)
    except ValueError: continue
    for k in ("Raw", "RawV2", "Redacted"): d.pop(k, None)   # drop values before anything is written
    print(json.dumps(d))' > "$OUT/trufflehog.jsonl"
  ARGS+=(--trufflehog "$OUT/trufflehog.jsonl")
fi

ghaudit secrets-plan "${ARGS[@]}" --name "$NAME" --csv "$OUT/rotation-plan.csv" --md "$OUT/summary.md"
cat "$OUT/summary.md"
echo
echo "Written: $OUT/summary.md, $OUT/rotation-plan.csv (scanner reports kept for the engagement; delete after the agreed retention)."
