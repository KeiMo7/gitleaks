#!/usr/bin/env bash
# End-to-end acceptance demo for `gitleaks changeset` (incremental scanning).
#
# The script builds a throwaway repository that mirrors the six required
# scenarios, runs full and incremental scans against the same commit and
# diffs every finding. It also measures timing for both modes.
set -euo pipefail

BINARY="${BINARY:-/tmp/gitleaks-inc}"
WORK="$(mktemp -d -t gitleaks-changeset-demo-XXXXXX)"
REPO="$WORK/demo-repo"
trap 'rm -rf "$WORK"' EXIT

echo "== workspace: $WORK"
mkdir -p "$REPO"
cd "$REPO"
git init -q -b main
git config user.name "Gitleaks Demo"
git config user.email "demo@example.com"
git config commit.gpgsign false

# A small, explicit rule set keeps the demo output readable and stable.
cat > .gitleaks.toml <<'TOML'
title = "incremental scan demo"
[[rules]]
  id = "aws-access-key"
  description = "AWS Access Key"
  regex = '''(?:AKIA|ASIA)[A-Z0-9]{16}'''
  keywords = ["akia", "asia"]
  tags = ["key", "AWS"]
TOML

mkdir -p src docs
cat > src/app.txt <<'EOF'
name: demo
region: us-east-1
EOF
cat > docs/notes.md <<'EOF'
# notes
pipeline config only
EOF
# The rename candidate must exist at the base so git classifies the later
# move as a rename rather than an add plus a delete.
mkdir -p src
cat > src/rename-me.txt <<EOF
moved = "AKIA1111111111111111"
EOF
git add . && git commit -q -m "initial import"
BASE=$(git rev-parse HEAD)
echo "== base commit: $BASE"

# 1. new file in a new directory (pure addition)
mkdir -p src/newdir
cat > src/newdir/credentials.txt <<EOF
added_secret = "AKIALALEMEL33243OLIA"
EOF
# 2. modified file (few lines changed)
cat > src/app.txt <<EOF
name: demo
region: us-west-2
rotated = "ASIA1234567890ABCDEF"
EOF
# 3. file destined for deletion
cat > src/doomed.txt <<EOF
legacy = "AKIA0000000000000000"
EOF
git add . && git commit -q -m "add candidates"
PRE_CHANGE=$(git rev-parse HEAD)

git rm -q src/doomed.txt
git mv src/rename-me.txt src/renamed.txt
# 5. mixed changeset also touches docs-only content
cat >> docs/notes.md <<EOF
- updated runbook
EOF
git add -A && git commit -q -m "delete, rename and docs"
HEAD_SHA=$(git rev-parse HEAD)

echo
echo "== changeset name-status ($BASE..$HEAD_SHA)"
git diff --name-status -M "$BASE" "$HEAD_SHA"

echo
echo "== [1/6] full directory scan at HEAD"
set +e
"$BINARY" dir --no-banner --log-level info \
  --report-format json --report-path "$WORK/full.json" . ; FULL_EXIT=$?
set -e
echo "full scan exit code: $FULL_EXIT"

echo
echo "== [2/6] incremental changeset scan ($BASE..HEAD)"
set +e
"$BINARY" changeset --no-banner --log-level info \
  --range "${BASE}..${HEAD_SHA}" \
  --report-format json --report-path "$WORK/inc.json" . ; INC_EXIT=$?
set -e
echo "incremental scan exit code: $INC_EXIT"

echo
echo "== [3/6] finding-level parity diff (must be empty)"
# Compare the stable identity of every finding for touched files.
jq -S 'map(select(.File|startswith("src/")))
       | map({file:.File,rule:.RuleID,start:.StartLine,col:.StartColumn,end_line:.EndLine,end_col:.EndColumn,secret:.Secret})
       | sort_by(.file,.rule,.start,.col)' "$WORK/full.json" > "$WORK/full.norm.json"
jq -S 'map({file:.File,rule:.RuleID,start:.StartLine,col:.StartColumn,end_line:.EndLine,end_col:.EndColumn,secret:.Secret})
       | sort_by(.file,.rule,.start,.col)' "$WORK/inc.json" > "$WORK/inc.norm.json"
if diff -u "$WORK/full.norm.json" "$WORK/inc.norm.json"; then
  echo "PARITY OK: zero differences"
else
  echo "PARITY FAILED" >&2
  exit 1
fi

echo
echo "== [4/6] empty changeset (docs-only diff against current HEAD)"
"$BINARY" changeset --no-banner --log-level info \
  --range "${HEAD_SHA}..${HEAD_SHA}" \
  --report-format json --report-path "$WORK/empty.json" . ; EMPTY_EXIT=$?
echo "empty changeset exit code: $EMPTY_EXIT"
echo "empty report contents:"
cat "$WORK/empty.json"

echo
echo "== [5/6] stdin file list + missing file skip"
set +e
printf 'src/app.txt\nsrc/does-not-exist.txt\n' | "$BINARY" changeset --no-banner --log-level info \
  --stdin --report-format json --report-path "$WORK/stdin.json" .
STDIN_EXIT=$?
set -e
echo "stdin scan exit code: $STDIN_EXIT"
jq -S 'map(.File)' "$WORK/stdin.json"

echo
echo "== [6/6] determinism: two incremental runs must be byte-identical"
"$BINARY" changeset --no-banner --log-level error \
  --range "${BASE}..${HEAD_SHA}" --report-format json --report-path "$WORK/run1.json" . || true
"$BINARY" changeset --no-banner --log-level error \
  --range "${BASE}..${HEAD_SHA}" --report-format json --report-path "$WORK/run2.json" . || true
if cmp -s "$WORK/run1.json" "$WORK/run2.json"; then
  echo "DETERMINISM OK: reports are byte-identical"
else
  echo "DETERMINISM FAILED" >&2
  exit 1
fi

echo
echo "== baseline metadata + corrupted baseline handling"
"$BINARY" changeset --no-banner --log-level info \
  --range "${BASE}..${HEAD_SHA}" --record-baseline-meta \
  --report-format json --report-path "$WORK/baseline.json" . || true
echo "sidecar metadata:"
cat "$WORK/baseline.json.meta.json"
echo
echo "corrupted sidecar failure (exit code shown below):"
echo '{broken' > "$WORK/baseline.json.meta.json"
set +e
"$BINARY" changeset --no-banner --log-level error \
  --range "${BASE}..${HEAD_SHA}" --baseline-path "$WORK/baseline.json" .
echo "corrupted baseline exit code: $?"
set -e

echo
echo "== timing comparison (3 runs each), same changeset"
echo "-- full scans --"
for i in 1 2 3; do
  set +e
  /usr/bin/time -f "full run $i: %e s" "$BINARY" dir --no-banner --log-level error \
    --report-format json --report-path "$WORK/t-full.json" .
  set -e
done
echo "-- incremental scans --"
for i in 1 2 3; do
  set +e
  /usr/bin/time -f "incremental run $i: %e s" "$BINARY" changeset --no-banner --log-level error \
    --range "${BASE}..${HEAD_SHA}" --report-format json --report-path "$WORK/t-inc.json" .
  set -e
done

echo
echo "== report snippets"
echo "-- incremental report (first 40 lines) --"
head -40 "$WORK/inc.json"
