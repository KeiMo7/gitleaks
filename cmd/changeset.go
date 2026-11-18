package cmd

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
	"github.com/zricethezav/gitleaks/v8/version"
)

func init() {
	rootCmd.AddCommand(changesetCmd)
	changesetCmd.Flags().StringArray("range", nil, "git revision range to scan, repeatable (e.g. main..HEAD, ^abc123, HEAD~1)")
	changesetCmd.Flags().Bool("staged", false, "scan staged changes (index) instead of a revision range")
	changesetCmd.Flags().Bool("stdin", false, "read a newline/NUL separated list of files to scan from stdin")
	changesetCmd.Flags().String("revision", "", "git revision used with --stdin file lists (defaults to the working tree)")
	changesetCmd.Flags().Bool("record-baseline-meta", false, "write baseline metadata next to --report-path so later runs can validate the baseline and detect rule changes")
}

var changesetCmd = &cobra.Command{
	Use:   "changeset [flags] [repo]",
	Short: "scan only the files in a changeset (incremental scan)",
	Long: `Incremental scan that feeds only the files touched by one or more git
revision ranges, staged changes, or a stdin file list through the same rule
engine used by full scans. Findings for a given file are identical to a full
scan of that file.

An empty changeset is reported and exits successfully.`,
	Args: cobra.MaximumNArgs(1),
	Run:  runChangeset,
}

func runChangeset(cmd *cobra.Command, args []string) {
	start := time.Now()

	source := "."
	if len(args) == 1 && args[0] != "" {
		source = args[0]
	}

	initConfig(source)
	initDiagnostics()
	cfg := Config(cmd)
	detector := Detector(cmd, cfg, source)

	exitCode := mustGetIntFlag(cmd, "exit-code")
	ranges, _ := cmd.Flags().GetStringArray("range")
	staged, _ := cmd.Flags().GetBool("staged")
	fromStdin, _ := cmd.Flags().GetBool("stdin")
	revision, _ := cmd.Flags().GetString("revision")
	recordMeta, _ := cmd.Flags().GetBool("record-baseline-meta")

	changeset, err := resolveChangeset(cmd.Context(), source, ranges, staged, fromStdin, revision)
	if err != nil {
		logging.Fatal().Err(err).Msg("could not resolve changeset")
	}

	logChangeset(changeset)

	// Validate baseline provenance before scanning so a corrupted or
	// incompatible baseline can never be silently treated as empty.
	rulesChanged := validateBaseline(cmd, cfg)

	var findings []report.Finding
	if len(changeset.Scannable()) > 0 {
		findings, err = detector.DetectChangeset(cmd.Context(), changeset, rulesChanged)
		if err != nil {
			logging.Error().Err(err).Msg("changeset scan failed")
		}
	} else {
		logging.Info().Msg("no scannable content in changeset; nothing to scan")
		findings = detector.Findings()
	}

	report.SortFindings(findings)

	if recordMeta && detector.ReportPath != "" && detector.ReportPath != report.StdoutReportPath {
		if metaErr := detect.WriteBaselineMeta(detector.ReportPath, cfg); metaErr != nil {
			logging.Error().Err(metaErr).Msg("could not write baseline metadata")
		}
	}

	changesetSummaryAndExit(detector, findings, exitCode, start, err)
}

// resolveChangeset turns the command flags into a stably ordered changeset.
func resolveChangeset(ctx context.Context, repoPath string, ranges []string, staged, fromStdin bool, revision string) (*sources.Changeset, error) {
	switch {
	case fromStdin:
		changeset, err := sources.NewChangesetFromReader(repoPath, os.Stdin)
		if err != nil {
			return nil, err
		}
		if revision != "" {
			annotateRevision(changeset, revision)
		}
		return changeset, nil
	case staged:
		return sources.NewChangesetFromDiff(ctx, repoPath, true)
	case len(ranges) > 0:
		return sources.NewChangesetFromRanges(ctx, repoPath, ranges)
	default:
		// Default to unstaged working tree changes so pre-commit style
		// pipelines work without extra flags.
		return sources.NewChangesetFromDiff(ctx, repoPath, false)
	}
}

// annotateRevision assigns a target revision to every stdin-provided change,
// switching content resolution from the working tree to git blobs.
func annotateRevision(changeset *sources.Changeset, revision string) {
	for index := range changeset.Files {
		changeset.Files[index].TargetRevision = revision
	}
}

// validateBaseline loads and checks the baseline sidecar. It reports whether
// the effective rule set differs from the one used to write the baseline.
func validateBaseline(cmd *cobra.Command, cfg config.Config) bool {
	baselinePath, _ := cmd.Flags().GetString("baseline-path")
	if baselinePath == "" {
		return false
	}

	// The shared Detector() loader only logs report parse errors. Incremental
	// scans must fail loudly on a corrupted baseline instead of silently
	// scanning with an empty one, so re-validate the report explicitly.
	if _, err := detect.LoadBaseline(baselinePath); err != nil {
		logging.Fatal().Err(err).Msg("baseline validation failed")
	}

	meta, ok, err := detect.LoadBaselineMeta(baselinePath)
	if err != nil {
		// Corruption or an unsupported schema are hard failures: scanning with
		// an assumed-empty baseline would suppress nothing and mislead users.
		logging.Fatal().Err(err).Msg("baseline validation failed")
	}
	if !ok {
		logging.Warn().
			Str("path", detect.BaselineMetaPath(baselinePath)).
			Msg("no baseline metadata found; rule-change detection disabled, regenerate with --record-baseline-meta")
		return false
	}

	if meta.GitleaksVersion != version.Version {
		logging.Warn().
			Str("baseline", meta.GitleaksVersion).
			Str("current", version.Version).
			Msg("baseline was written by a different gitleaks version")
	}

	currentChecksum := detect.RulesChecksum(cfg)
	rulesChanged := meta.RulesChecksum != currentChecksum
	if rulesChanged {
		logging.Warn().
			Str("baseline_checksum", meta.RulesChecksum).
			Str("current_checksum", currentChecksum).
			Msg("rule set changed since the baseline was written; historical findings may resurface")
	}
	return rulesChanged
}

func logChangeset(changeset *sources.Changeset) {
	var added, modified, deleted, renamed int
	for _, change := range changeset.Files {
		switch change.Kind {
		case sources.ChangeAdded:
			added++
		case sources.ChangeModified:
			modified++
		case sources.ChangeDeleted:
			deleted++
		case sources.ChangeRenamed:
			renamed++
		}
	}

	logging.Info().
		Int("total", len(changeset.Files)).
		Int("added", added).
		Int("modified", modified).
		Int("deleted", deleted).
		Int("renamed", renamed).
		Int("scannable", len(changeset.Scannable())).
		Msg("changeset resolved")

	for _, change := range changeset.Files {
		event := logging.Debug().Str("path", change.Path).Str("change", change.Kind.String())
		if change.OldPath != "" {
			event = event.Str("old_path", change.OldPath)
		}
		event.Msg("changeset entry")
	}
}

// changesetSummaryAndExit mirrors findingSummaryAndExit but writes the report
// atomically: the output file is never left half-written when a scan fails
// midway.
func changesetSummaryAndExit(detector *detect.Detector, findings []report.Finding, exitCode int, start time.Time, scanErr error) {
	if diagnosticsManager.Enabled {
		logging.Debug().Msg("Finalizing diagnostics...")
		diagnosticsManager.StopDiagnostics()
	}

	totalBytes := detector.TotalBytes.Load()
	if scanErr == nil {
		logging.Info().Msgf("scanned ~%d bytes (%s) in %s", totalBytes, bytesConvert(totalBytes), FormatDuration(time.Since(start)))
		if len(findings) != 0 {
			logging.Warn().Msgf("leaks found: %d", len(findings))
		} else {
			logging.Info().Msg("no leaks found")
		}
	} else {
		logging.Warn().Msgf("partial scan completed in %s, %d leaks found so far", FormatDuration(time.Since(start)), len(findings))
	}

	if detector.Reporter != nil {
		if reportErr := writeReportAtomic(detector, findings); reportErr != nil {
			logging.Fatal().Err(reportErr).Msg("failed to write report")
		}
	}

	if scanErr != nil {
		os.Exit(1)
	}
	if len(findings) != 0 {
		os.Exit(exitCode)
	}
}

// writeReportAtomic renders to a temp file in the same directory and renames
// it into place, so readers never observe a truncated report.
func writeReportAtomic(detector *detect.Detector, findings []report.Finding) error {
	if detector.ReportPath == report.StdoutReportPath {
		return detector.Reporter.Write(os.Stdout, findings)
	}

	dir := filepath.Dir(detector.ReportPath)
	tmp, err := os.CreateTemp(dir, ".gitleaks-report-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	writeErr := detector.Reporter.Write(tmp, findings)
	closeErr := tmp.Close()
	if writeErr != nil {
		_ = os.Remove(tmpName)
		return writeErr
	}
	if closeErr != nil {
		_ = os.Remove(tmpName)
		return closeErr
	}

	return os.Rename(tmpName, detector.ReportPath)
}
