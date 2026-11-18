package detect

import (
	"context"

	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

// DetectChangeset scans only the files touched by a changeset using the same
// detector pipeline as a full scan, so every finding matches the full scan
// result for the same file (rule id, location, columns and secret).
//
// When rulesChanged is true, the pre-image of each changed file is scanned
// as well; findings that already existed before the change are classified as
// rule-driven re-introductions (see Detector.IsRuleChange) rather than new
// problems. Rename history is honoured through the changeset aliases.
func (d *Detector) DetectChangeset(ctx context.Context, changeset *sources.Changeset, rulesChanged bool) ([]report.Finding, error) {
	d.SetPathAliases(changeset.RenameAliases())

	scannable := changeset.Scannable()
	if len(scannable) == 0 {
		logging.Info().Msg("changeset contains no files to scan")
		return d.Findings(), nil
	}

	if rulesChanged {
		d.classifyRuleChanges(ctx, changeset, scannable)
	}

	source := &sources.ChangesetSource{
		Changeset:       changeset,
		RepoPath:        changesetRepoPath(changeset),
		Config:          &d.Config,
		MaxArchiveDepth: d.MaxArchiveDepth,
	}

	findings, err := d.DetectSource(ctx, source)
	if err != nil {
		return findings, err
	}

	ruleChanges := d.RuleChangeFindings()
	if len(ruleChanges) > 0 {
		logging.Warn().
			Int("count", len(ruleChanges)).
			Msg("findings already present before this changeset; resurfaced by a rule change, not newly introduced")
	}

	return findings, nil
}

// classifyRuleChanges scans the base revision content of every changed file
// and records the fingerprints of every pre-existing finding. Added files
// have no pre-image and are naturally excluded.
func (d *Detector) classifyRuleChanges(ctx context.Context, changeset *sources.Changeset, scannable []sources.FileChange) {
	preimageChangeset := *changeset
	preimageChangeset.Files = scannable

	// The pre-image detector uses an isolated findings slice and ignore state
	// so baseline/gitleaksignore filtering never hides rule-change signals and
	// pre-image findings never leak into the report.
	preimageDetector := NewDetectorContext(ctx, d.Config)
	preimageDetector.MaxDecodeDepth = d.MaxDecodeDepth
	preimageDetector.MaxArchiveDepth = d.MaxArchiveDepth
	preimageDetector.MaxTargetMegaBytes = d.MaxTargetMegaBytes
	preimageDetector.IgnoreGitleaksAllow = d.IgnoreGitleaksAllow

	source := &sources.ChangesetSource{
		Changeset:       &preimageChangeset,
		RepoPath:        changesetRepoPath(changeset),
		Config:          &d.Config,
		MaxArchiveDepth: d.MaxArchiveDepth,
		Preimage:        true,
	}

	preimageFindings, err := preimageDetector.DetectSource(ctx, source)
	if err != nil {
		logging.Warn().Err(err).Msg("could not fully scan pre-image; rule-change classification may be partial")
	}

	// Pre-image findings use old paths for renamed files. Re-key them onto the
	// current path so fingerprints line up with the post-image findings.
	aliases := changeset.RenameAliases()
	for current, old := range aliases {
		for index := range preimageFindings {
			if preimageFindings[index].File == old {
				preimageFindings[index].File = current
			}
		}
	}

	d.AddPreExistingFingerprints(preimageFindings)
	logging.Debug().Int("count", len(preimageFindings)).Msg("pre-image findings recorded for rule-change classification")
}

// changesetRepoPath centralises where the repository path is stored. The
// changeset itself is revision/path oriented; the source needs a working tree
// path for filesystem and git invocations.
func changesetRepoPath(changeset *sources.Changeset) string {
	// Stored via ChangesetOptions when constructed by the command layer.
	return changeset.RepoPath()
}
