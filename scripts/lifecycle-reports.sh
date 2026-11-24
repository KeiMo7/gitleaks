#!/usr/bin/env bash
# Generates real end-to-end lifecycle reports into reports/.
#
# The scenarios mirror the acceptance tests: add, rotate, delete, rename and
# cross-branch merge. Each scenario gets a fresh temporary repository, and the
# exact CLI output is written next to a summary so the conclusions can be
# reviewed without re-running anything.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORTS="$ROOT/reports"
BIN="$ROOT/.work/gitleaks"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$REPORTS"

export GIT_AUTHOR_NAME="Lifecycle E2E"
export GIT_AUTHOR_EMAIL="lifecycle@example.com"
export GIT_COMMITTER_NAME="Lifecycle E2E"
export GIT_COMMITTER_EMAIL="lifecycle@example.com"

cat >"$WORK/config.toml" <<'TOML'
title = "lifecycle report generation"
[[rules]]
    id = "lit-token"
    description = "Literal test token"
    regex = '''LCK_[A-Z0-9]{4}\s*[A-Z0-9]{4}'''
    keywords = ["LCK_"]

[[rules]]
    id = "alt-token"
    description = "Alternate literal test token"
    regex = '''LCK_(?:ALPHA|BETA)[A-Z0-9]{3}'''
    keywords = ["LCK_"]
TOML

commit() {
  local dir="$1" date="$2" msg="$3"
  ( cd "$dir"
    GIT_AUTHOR_DATE="$date" GIT_COMMITTER_DATE="$date" git add -A
    GIT_AUTHOR_DATE="$date" GIT_COMMITTER_DATE="$date" git commit -q --allow-empty -m "$msg"
  )
}

init_repo() {
  local dir="$1"
  mkdir -p "$dir"
  git -C "$dir" init -q -b main
  cp "$WORK/config.toml" "$dir/.gitleaks.toml"
}

scan() {
  local name="$1" dir="$2"
  shift 2
  "$BIN" git "$dir" \
    --config "$dir/.gitleaks.toml" \
    --report-path "$REPORTS/$name.findings.json" \
    --report-format json \
    --lifecycle \
    --lifecycle-report-path "$REPORTS/$name.lifecycle.json" \
    --log-level error --no-banner "$@" >"$REPORTS/$name.stdout.txt" 2>"$REPORTS/$name.stderr.txt" || true
}

# --- Scenario 1: added, then rotated, then deleted -------------------------
S="$WORK/add-rotate-delete"
init_repo "$S"
mkdir -p "$S"
printf 'TOKEN=LCK_AAAA1111\n' >"$S/app.env"
commit "$S" "2020-01-01T00:00:00Z" "add secret one"
printf 'TOKEN=LCK_BBBB2222\n' >"$S/app.env"
commit "$S" "2020-02-01T00:00:00Z" "rotate to secret two"
printf 'TOKEN=none\n' >"$S/app.env"
commit "$S" "2020-03-01T00:00:00Z" "remove secret two"
scan "add-rotate-delete" "$S"

# --- Scenario 2: rename + encoded + split forms ----------------------------
S="$WORK/rename-encoded"
init_repo "$S"
mkdir -p "$S/configs"
printf 'TOKEN=LCK_AAAA1111\n' >"$S/configs/old.env"
commit "$S" "2020-01-01T00:00:00Z" "add"
( cd "$S" && git mv configs/old.env configs/new.env )
commit "$S" "2020-02-01T00:00:00Z" "move"
printf '# base64 of LCK_AAAA1111\nB64=TENLX0FBQUExMTEx\nSPLIT=LCK_AAAA\n1111\n' >"$S/configs/new.env"
commit "$S" "2020-03-01T00:00:00Z" "encoded and split forms"
scan "rename-encoded" "$S"

# --- Scenario 3: merged and unmerged branches ------------------------------
S="$WORK/branches"
init_repo "$S"
printf 'base\n' >"$S/base.txt"
commit "$S" "2020-01-01T00:00:00Z" "base"

( cd "$S" && git checkout -q -b merged-feature )
printf 'TOKEN=LCK_CCCC3333\n' >"$S/merged.env"
commit "$S" "2020-02-01T00:00:00Z" "merged feature secret"

( cd "$S" && git checkout -q -b unmerged-feature main )
printf 'TOKEN=LCK_DDDD4444\n' >"$S/unmerged.env"
commit "$S" "2020-03-01T00:00:00Z" "unmerged feature secret"

( cd "$S" && git checkout -q main )
printf 'main work\n' >"$S/main.txt"
commit "$S" "2020-04-01T00:00:00Z" "main work"
( cd "$S" && git merge -q --no-ff merged-feature -m "merge feature" )
printf 'TOKEN=none\n' >"$S/merged.env"
commit "$S" "2020-05-01T00:00:00Z" "remove merged secret"
scan "branches" "$S"

# --- Scenario 4: directory scan (no history) -------------------------------
S="$WORK/directory"
mkdir -p "$S"
cp "$WORK/config.toml" "$S/.gitleaks.toml"
printf 'TOKEN=LCK_EEEE5555\n' >"$S/app.env"
( cd "$S" && "$BIN" dir . \
  --config .gitleaks.toml \
  --report-path "$REPORTS/directory.findings.json" \
  --report-format json \
  --lifecycle \
  --lifecycle-report-path "$REPORTS/directory.lifecycle.json" \
  --log-level error --no-banner >"$REPORTS/directory.stdout.txt" 2>"$REPORTS/directory.stderr.txt" ) || true

# --- Scenario 5: shallow clone (incomplete history) ------------------------
S="$WORK/shallow-src"
init_repo "$S"
printf 'base\n' >"$S/base.txt"
commit "$S" "2020-01-01T00:00:00Z" "base"
printf 'TOKEN=LCK_FFFF6666\n' >"$S/app.env"
commit "$S" "2020-02-01T00:00:00Z" "add secret"
git clone -q --depth 1 "file://$S" "$WORK/shallow"
cp "$WORK/config.toml" "$WORK/shallow/.gitleaks.toml"
scan "shallow" "$WORK/shallow"

# --- Scenario 6: byte-for-byte determinism ---------------------------------
S="$WORK/determinism"
init_repo "$S"
printf 'TOKEN=LCK_AAAA1111\n' >"$S/a.env"
commit "$S" "2020-01-01T00:00:00Z" "one"
printf 'TOKEN=LCK_BBBB2222\n' >"$S/a.env"
commit "$S" "2020-02-01T00:00:00Z" "two"
printf 'TOKEN=none\n' >"$S/a.env"
commit "$S" "2020-03-01T00:00:00Z" "three"
scan "determinism-run1" "$S"
scan "determinism-run2" "$S"
cmp "$REPORTS/determinism-run1.lifecycle.json" "$REPORTS/determinism-run2.lifecycle.json"
cmp "$REPORTS/determinism-run1.findings.json" "$REPORTS/determinism-run2.findings.json"
( cd "$REPORTS" && sha256sum determinism-run1.* determinism-run2.* >determinism.sha256 )

# --- Scenario 7: restricted history (--log-opts) ---------------------------
S="$WORK/restricted"
init_repo "$S"
printf 'base\n' >"$S/base.txt"
commit "$S" "2020-01-01T00:00:00Z" "base"
printf 'TOKEN=LCK_GGGG7777\n' >"$S/app.env"
commit "$S" "2020-02-01T00:00:00Z" "add secret"
SECRET_COMMIT="$(git -C "$S" rev-parse HEAD)"
printf 'TOKEN=none\n' >"$S/app.env"
commit "$S" "2020-03-01T00:00:00Z" "remove secret"
scan "restricted-history" "$S" --log-opts "$SECRET_COMMIT^..$SECRET_COMMIT"

echo "reports written to $REPORTS"
