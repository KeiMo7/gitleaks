# Incremental (changeset) scanning

This document describes the `gitleaks changeset` command added for pipeline
use cases where a full scan of a large repository dominates build time but
most commits only touch a handful of files.

## Goals and constraints

The implementation is bound by the same hard constraints as the rest of
gitleaks:

- Reuse the existing rule engine and report formats. No second matching
  implementation exists.
- For any given file, an incremental finding is identical to a full-scan
  finding: rule id, description, line/column, match, secret, tags and
  fingerprint.
- Existing baselines and `.gitleaksignore` keep working, including across
  renames.
- No new third-party dependencies and no meaningful binary size increase.
- Deterministic, byte-identical output for identical inputs.

## Components

| File | Responsibility |
| --- | --- |
| `sources/changeset.go` | Resolves a change set from git revision ranges, working-tree diffs or a stdin file list. Parses NUL-delimited `git diff --name-status -z -M` output (adds, modifications, deletes, renames), unions multiple ranges, de-duplicates and sorts entries by path. |
| `sources/changeset_source.go` | `Source` implementation that yields fragments for the scannable files of a change set, in stable order. Reads working-tree files from disk and revision blobs through the batch reader. Missing files are logged and skipped. |
| `sources/blob_batch.go` | A single long-lived `git cat-file --batch` process serving every blob in the change set, avoiding one process fork per file. |
| `detect/changeset.go` | Orchestration: rename aliases, optional pre-image scan for rule-change classification, then the standard `DetectSource` pipeline. |
| `detect/baseline_meta.go` | Baseline sidecar format (schema version, gitleaks version, rule-set checksum), load/validate/write helpers. |
| `detect/detect.go` | Rename-aware `.gitleaksignore`/baseline matching and pre-existing fingerprint tracking. |
| `report/sort.go` | Stable finding ordering used before writing reports. |
| `cmd/changeset.go` | The `changeset` CLI, baseline validation and atomic report writes. |

## Why findings match full scans

`ChangesetSource` builds the same `sources.File` value that the directory
scanner uses and hands it to the same `Detector.DetectSource` call. The
detector therefore runs the identical keyword prefilter, regex rules,
allowlists, entropy checks, codec/decoder passes and archive handling.

Two deliberate differences keep the output coherent:

1. **No commit metadata.** Incremental findings describe the current content
   of a file rather than a historical patch, so `Commit`, author and date
   fields are empty, exactly like a `gitleaks dir` scan of the same tree.
   The commit-less fingerprint is `file:rule:startLine`.
2. **Whole-file content.** Even when only a few lines changed, the complete
   post-image (or working-tree) content is scanned, not just the diff hunks.
   This is what makes line numbers and matches identical to a full scan and
   keeps multi-line rules correct.

Deletions never yield fragments, so deleted files cannot appear in results.
Renames carry `OldPath`; the detector substitutes the old path only when
matching `.gitleaksignore` fingerprints and baseline entries, never in the
reported `File` field.

## Change set inputs

- `--range A..B` (repeatable): each range is converted to
  `git diff --name-status -z -M A B`. Ranges are unioned by path; a delete
  later in the union wins, and re-added files are scanned.
- `--staged` / default (no flags): `git diff` against the index or the
  working tree respectively.
- `--stdin`: newline/NUL separated paths. Missing paths are classified as
  deletions so they are skipped, not fatal.
- `--stdin --revision R`: the same path list resolved against git blobs at
  revision `R` instead of the working tree.

All paths are normalized to `/` separators and the final list is sorted
lexicographically. Files are then visited serially in that order, which
guarantees deterministic output regardless of goroutine scheduling.

## Rule-change classification

When baseline metadata records a different rule-set checksum, the pre-image
of every changed file is scanned with an isolated detector. The fingerprints
of pre-existing findings are recorded with a line-independent key
(`file|rule|secret`), because an unrelated edit above a secret shifts its
line number even though the secret itself is unchanged. Post-image findings
matching that key are reported as rule-driven re-introductions via
`Detector.IsRuleChange` / `RuleChangeFindings` and logged with a warning;
they remain in the report so full-scan parity is preserved.

## Failure handling

- **Empty change set**: info-level "no scannable content", empty report
  written when requested, exit code 0.
- **Corrupt baseline / unsupported sidecar schema**: fatal error before
  scanning; the tool never assumes an empty baseline.
- **Missing sidecar**: warning and continued execution with rule-change
  detection disabled (baselines produced by older versions stay usable).
- **Missing file in the change set**: warning per file, scan continues.
- **Mid-scan failure**: reports are rendered to a temp file in the target
  directory and renamed into place only on success, so a partial failure
  never leaves a truncated report. Findings collected so far stay available
  through the detector.

## Testing

- `sources/changeset_test.go`: name-status parsing (add/modify/delete/
  rename/mixed), range parsing, union/de-duplication, working-tree and
  stdin change sets, empty change set, deterministic ordering.
- `detect/changeset_test.go`: the six required end-to-end scenarios on
  throwaway git repositories (new file in a new directory, modification with
  full-scan parity, deletion, rename, mixed change set, empty set), plus
  missing-file skip and byte-level determinism.
- `detect/changeset_rules_test.go`: rule-driven re-introduction, baseline
  sidecar round trip, corruption/schema failures, rename-aware baselines.
- `scripts/acceptance/demo.sh`: black-box CLI acceptance including parity
  diff, exit codes and report snippets.

## Observed performance

Measured on a synthetic 12,004-file repository (61 commits, ~80 lines per
file, default rule set) with a single-commit, three-file change set:

| Scan | Wall time (best of 3) |
| --- | --- |
| Full `gitleaks dir` | ~1.9 s |
| Incremental `gitleaks changeset` | ~0.2 s |
| Empty change set (fixed overhead) | ~0.02 s |

The fixed overhead per invocation is dominated by process startup and
loading/compiling the embedded rule set (~20-30 ms); resolving the change
set with `git diff --name-status` is below 5 ms even at this scale. Blob
reads are served by one `git cat-file --batch` process, so revision-based
scans do not pay a fork per file. On the smaller 5,000-file fixture the
same change set runs in ~0.06 s versus ~0.17 s for a full scan.
