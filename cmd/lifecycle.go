package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"

	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/lifecycle"
	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/report"
)

func init() {
	rootCmd.PersistentFlags().Bool("lifecycle", false, "enable the secret lifecycle analysis (first/last seen, current use, branch membership)")
	rootCmd.PersistentFlags().String("lifecycle-report-path", "", "write the lifecycle report here (requires --lifecycle)")
	rootCmd.PersistentFlags().String("lifecycle-salt", "", "additional salt for lifecycle identifiers; repository identity is always mixed in")
	rootCmd.PersistentFlags().Int("lifecycle-chunk-size", lifecycle.DefaultChunkSize, "occurrence records buffered in memory before spilling to disk")
	rootCmd.PersistentFlags().String("lifecycle-default-branch", "", "branch whose tip decides whether a secret is still in use (default: origin/HEAD, checked-out branch, then main/master)")
}

// lifecycleSession owns everything needed to produce a lifecycle report: the
// spool, the repository handle and the hasher. A nil session means the
// feature is off and scan behavior is unchanged.
type lifecycleSession struct {
	kind   lifecycle.Kind
	source string

	spool  *lifecycle.Spool
	repo   *lifecycle.Repo
	hasher *lifecycle.Hasher
	rec    *detect.Lifecycle
	tip    string
	opts   lifecycle.Options

	report  string
	workDir string

	newDetector func() *detect.Detector
}

// newLifecycleSession initializes the feature. Problems disable the feature
// with a log line; lifecycle analysis never changes scan exit behavior.
func newLifecycleSession(cmd *cobra.Command, kind lifecycle.Kind, source string, cmdName string) *lifecycleSession {
	enabled, err := cmd.Flags().GetBool("lifecycle")
	if err != nil || !enabled {
		return nil
	}

	s := &lifecycleSession{kind: kind, source: source}

	reportPath, _ := cmd.Flags().GetString("lifecycle-report-path")
	if reportPath == "" {
		reportPath = "lifecycle-report.json"
		if source != "" && source != "." {
			if info, statErr := os.Stat(source); statErr == nil && info.IsDir() {
				reportPath = filepath.Join(source, "lifecycle-report.json")
			}
		}
	}
	s.report = reportPath

	workDir, err := os.MkdirTemp("", "gitleaks-lifecycle-")
	if err != nil {
		logging.Error().Err(err).Msg("lifecycle: could not create spool directory; lifecycle analysis disabled")
		return nil
	}
	s.workDir = workDir

	chunkSize, _ := cmd.Flags().GetInt("lifecycle-chunk-size")
	s.spool, err = lifecycle.NewSpool(workDir, chunkSize)
	if err != nil {
		logging.Error().Err(err).Msg("lifecycle: could not create spool; lifecycle analysis disabled")
		_ = os.RemoveAll(workDir)
		return nil
	}

	s.opts = lifecycle.Options{
		Kind:            kind,
		HistoryComplete: true,
		FullHistory:     kind == lifecycle.KindGit,
	}
	if kind != lifecycle.KindGit {
		s.opts.HistoryReasons = []string{fmt.Sprintf("%s scan has no git history", kind)}
	}

	if kind == lifecycle.KindGit {
		repo := lifecycle.NewRepo(source)
		if !repo.IsRepositoryRoot(cmd.Context()) {
			logging.Warn().Msg("lifecycle: source is not a git repository; conclusions are marked no-history")
			s.kind = lifecycle.KindDirectory
			s.opts.Kind = lifecycle.KindDirectory
			s.opts.FullHistory = false
			s.opts.HistoryReasons = []string{"source is not a git repository"}
		} else {
			s.repo = repo
			s.opts.DefaultBranch, _ = cmd.Flags().GetString("lifecycle-default-branch")
			if s.opts.DefaultBranch == "" {
				if b, err := repo.SymbolicDefaultBranch(cmd.Context()); err == nil {
					s.opts.DefaultBranch = b
				}
			}
			if s.opts.DefaultBranch != "" {
				if sha, err := repo.ResolveCommit(cmd.Context(), "refs/heads/"+s.opts.DefaultBranch); err == nil {
					s.tip = sha
				} else if sha, err := repo.ResolveCommit(cmd.Context(), s.opts.DefaultBranch); err == nil {
					s.tip = sha
				}
			}

			logOpts, _ := cmd.Flags().GetString("log-opts")
			if cmdName == "protect" {
				logOpts = "pre-commit"
			}
			if logOpts != "" {
				s.opts.FullHistory = false
				s.opts.HistoryReasons = append(s.opts.HistoryReasons,
					"history restricted by --log-opts; conclusions cover the selected revisions only")
			}
			if cmdName == "detect" || cmdName == "git" {
				if staged, _ := cmd.Flags().GetBool("staged"); staged {
					s.opts.FullHistory = false
				}
				if pre, _ := cmd.Flags().GetBool("pre-commit"); pre {
					s.opts.FullHistory = false
				}
			}
		}
	}

	salt, _ := cmd.Flags().GetString("lifecycle-salt")
	var roots []string
	var remote string
	if s.repo != nil {
		roots = s.repo.RootCommits(cmd.Context())
		remote = s.repo.RemoteURL(cmd.Context())
	}
	fingerprint := lifecycle.RepoFingerprint(s.kind, source, roots, remote)
	s.hasher = lifecycle.NewHasherWithPepper(fingerprint, salt)

	s.rec = &detect.Lifecycle{Spool: s.spool, Hasher: s.hasher}
	if s.repo != nil {
		repo := s.repo
		s.rec.PathMap = func(path string) string {
			return repo.PathAtCommit(context.Background(), path)
		}
	}
	return s
}

// attach installs the recorder on a detector.
func (s *lifecycleSession) attach(d *detect.Detector) {
	if s == nil {
		return
	}
	d.Lifecycle = s.rec
}

// finish analyzes the spool, annotates findings and writes the report.
// Failures are logged; the scan's findings and exit code are unchanged.
func (s *lifecycleSession) finish(ctx context.Context, detector *detect.Detector, findings []report.Finding) {
	if s == nil {
		return
	}
	defer func() {
		_ = s.spool.Close()
		_ = os.RemoveAll(s.workDir)
	}()

	// Findings are produced concurrently, so their order depends on
	// scheduling. Sort them only when lifecycle analysis is enabled so two
	// runs on the same repository and configuration emit identical bytes.
	sortFindings(findings)

	var tipScan lifecycle.TipScanFunc
	if s.repo != nil && s.tip != "" && s.newDetector != nil {
		tipScan = (&detect.TipScanner{
			NewDetector: s.newDetector,
			Hasher:      s.hasher,
		}).ScanBlob
	}

	if s.rec != nil {
		scanErrors, largeFragments := s.rec.Diagnostics()
		s.opts.ScanErrors += scanErrors
		s.opts.SkippedLargeFragments += largeFragments
	}
	if detector != nil && detector.MaxTargetMegaBytes > 0 {
		// Apply the same size limit to tip blobs that the scan applies to
		// fragments, and count skips instead of silently dropping them.
		s.opts.MaxBlobBytes = int64(detector.MaxTargetMegaBytes) * 1_000_000
	}

	analyzer := lifecycle.NewAnalyzer(s.repo, s.spool, s.tip, tipScan, s.opts)

	out, err := os.Create(s.report)
	if err != nil {
		logging.Error().Err(err).Msg("lifecycle: could not create report")
		attachLifecycleInfo(s, findings, nil)
		return
	}
	summary, infos, analyzeErr := analyzer.Analyze(ctx, out)
	if closeErr := out.Close(); closeErr != nil && analyzeErr == nil {
		analyzeErr = closeErr
	}
	attachLifecycleInfo(s, findings, infos)
	if analyzeErr != nil {
		logging.Error().Err(analyzeErr).Msg("lifecycle: analysis failed")
		return
	}
	if summary == nil {
		return
	}
	logging.Info().Msgf(
		"lifecycle: %d secrets (%d in use, %d not in use, %d unknown, %d no-history) written to %s",
		summary.Secrets, summary.InUse, summary.NotInUse, summary.Unknown, summary.NoHistory, s.report,
	)
}

// sortFindings orders findings by every field that identifies a location, so
// the primary report is deterministic regardless of scan concurrency.
func sortFindings(findings []report.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := &findings[i], &findings[j]
		switch {
		case a.Commit != b.Commit:
			return a.Commit < b.Commit
		case a.File != b.File:
			return a.File < b.File
		case a.RuleID != b.RuleID:
			return a.RuleID < b.RuleID
		case a.StartLine != b.StartLine:
			return a.StartLine < b.StartLine
		case a.StartColumn != b.StartColumn:
			return a.StartColumn < b.StartColumn
		case a.EndLine != b.EndLine:
			return a.EndLine < b.EndLine
		case a.EndColumn != b.EndColumn:
			return a.EndColumn < b.EndColumn
		case a.Match != b.Match:
			return a.Match < b.Match
		default:
			return a.Fingerprint < b.Fingerprint
		}
	})
}

// attachLifecycleInfo enriches findings in place with the summary for their
// secret/rule pair. Findings whose secret was suppressed have no group and
// are left untouched.
func attachLifecycleInfo(s *lifecycleSession, findings []report.Finding, infos map[lifecycle.Key]lifecycle.Info) {
	if len(infos) == 0 {
		return
	}
	for i := range findings {
		id := findings[i].LifecycleSecretID
		if id == "" {
			if findings[i].Secret == "" {
				id = s.hasher.Digest("path\x00" + findings[i].File)
			} else {
				id = s.hasher.Digest(findings[i].Secret)
			}
		}
		info, ok := infos[lifecycle.Key{SecretID: id, RuleID: findings[i].RuleID}]
		if !ok {
			continue
		}
		copied := info
		findings[i].Lifecycle = &copied
	}
}
