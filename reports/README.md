# Lifecycle reports — captured real output

Everything here was produced by the built binary (`.work/gitleaks`) against
throwaway repositories created by `scripts/lifecycle-reports.sh`. Re-run with:

```sh
go build -o .work/gitleaks .
bash scripts/lifecycle-reports.sh
```

The repositories are deleted after generation, so commit SHAs differ between
runs; within one run the determinism files are compared byte for byte.

## Files

| File | What it shows |
| --- | --- |
| `add-rotate-delete.*` | Two secrets in the same slot, one rotated out and the second deleted: both `not-in-use`, each with its own first/last commit. |
| `rename-encoded.*` | One secret written plainly, then base64, then percent-encoded and split across a line break, after the file was moved: one row, four locations, canonical old path, `in-use`. |
| `branches.*` | One secret on a branch merged into `main` (`MergedRefs`), one on an unmerged branch (`HistoricalRefs`); both absent from the tip. |
| `directory.*` | A directory scan: `Source: directory`, `History.Complete: false`, every row `no-history`, no `InUse` value. |
| `shallow.*` | A depth-1 clone: `Repository.Shallow: true`, `History.Complete: false` with a reason, and no row claims absence. |
| `restricted-history.*` | `--log-opts` limiting the scan: history is explicitly incomplete and the secret is `unknown`, not `not-in-use`. |
| `determinism-run1/2.*` | Two identical runs; `determinism.sha256` lists identical hashes for both. |
| `test-logs/full-suite.log` | `go test ./... -v` — all packages pass. |
| `test-logs/lifecycle-tests.log` | The lifecycle package's unit, end-to-end and regression tests. |

Every `*.findings.json` is the normal gitleaks JSON report; each finding's
existing fields are unchanged and a `Lifecycle` object is appended last.
`*.stdout.txt` / `*.stderr.txt` are the captured streams (errors only would
appear there; they are empty for the success cases).

## What the columns mean

* `SecretID` — salted digest of the normalized secret. Repository-scoped, so
  it is not reusable across repositories, and it never contains plaintext.
* `Status` — `in-use`, `not-in-use`, `unknown`, or `no-history`.
* `FirstSeen` / `LastSeen` — earliest and latest commit (and commit date) the
  secret was observed in, ordered by commit date.
* `Refs` / `MergedRefs` / `HistoricalRefs` — branches and tags containing an
  occurrence, and which of them are reachable from the default-branch tip.
* `History.Complete` + `History.Reasons` — whether an absence conclusion is
  trustworthy, and why not when it is not.
* `Diagnostics` — counted degradations (unreadable refs/objects, git command
  failures/timeouts, oversized blobs/fragments) that were skipped rather than
  failing the scan.
* `Locations` — every retained hit, deduplicated only on identical position,
  with rename history folded onto the oldest known path.
