package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/logging"
)

func init() {
	rootCmd.AddCommand(marksCmd)
	marksCmd.AddCommand(marksSuppressCmd, marksRevokeCmd, marksListCmd)
	marksCmd.PersistentFlags().String("marks-path", "", "override the marks file path (defaults to the confidence config marks.path or .gitleaks-marks.json)")
	marksSuppressCmd.Flags().String("note", "", "optional human note for the suppression (do not put secret material here)")
}

var marksCmd = &cobra.Command{
	Use:   "marks",
	Short: "manage revocable false-positive marks (fingerprints only, never secret material)",
}

var marksSuppressCmd = &cobra.Command{
	Use:   "suppress <fingerprint> [fingerprint...]",
	Short: "mark one or more fingerprints as confirmed false positives",
	Args:  cobra.MinimumNArgs(1),
	Run:   runMarkSuppress,
}

var marksRevokeCmd = &cobra.Command{
	Use:   "revoke <fingerprint> [fingerprint...]",
	Short: "revoke a previous suppression so the finding is reported again",
	Args:  cobra.MinimumNArgs(1),
	Run:   runMarkRevoke,
}

var marksListCmd = &cobra.Command{
	Use:   "list",
	Short: "list all marks in stable order",
	Args:  cobra.NoArgs,
	Run:   runMarkList,
}

// resolveMarksStore opens the marks store using the same resolution order as
// a scan: --marks-path, then the confidence config marks.path, then the
// built-in default filename.
func resolveMarksStore(cmd *cobra.Command) (*detect.MarksStore, string) {
	path, _ := cmd.Flags().GetString("marks-path")
	if path == "" {
		if confidencePath, _ := cmd.Flags().GetString("confidence-config"); confidencePath != "" {
			cc, degraded := config.LoadConfidenceConfig(confidencePath)
			if degraded != nil && degraded.HardReject {
				logging.Fatal().Err(degraded).Msg("refusing to load confidence config")
			}
			if degraded != nil {
				logging.Warn().Err(degraded).Msg("using built-in default confidence thresholds")
			}
			path = cc.Marks.Path
		} else {
			path = config.DefaultConfidenceConfig().Marks.Path
		}
	}
	store, err := detect.NewMarksStore(path)
	if err != nil {
		logging.Fatal().Err(err).Msg("could not open marks store")
	}
	return store, path
}

func runMarkSuppress(cmd *cobra.Command, args []string) {
	store, path := resolveMarksStore(cmd)
	note, _ := cmd.Flags().GetString("note")
	for _, fp := range args {
		fp = strings.TrimSpace(fp)
		if fp == "" {
			continue
		}
		if err := store.Suppress(fp, note); err != nil {
			logging.Fatal().Err(err).Str("fingerprint", fp).Msg("could not suppress mark")
		}
		logging.Info().Str("fingerprint", fp).Str("marks", path).Msg("suppressed")
	}
}

func runMarkRevoke(cmd *cobra.Command, args []string) {
	store, _ := resolveMarksStore(cmd)
	for _, fp := range args {
		fp = strings.TrimSpace(fp)
		if err := store.Revoke(fp); err != nil {
			logging.Fatal().Err(err).Str("fingerprint", fp).Msg("could not revoke mark")
		}
		logging.Info().Str("fingerprint", fp).Msg("revoked")
	}
}

func runMarkList(cmd *cobra.Command, _ []string) {
	store, _ := resolveMarksStore(cmd)
	for _, m := range store.List() {
		line := fmt.Sprintf("%s\t%s", m.Status, m.Fingerprint)
		if m.Note != "" {
			line += "\t" + m.Note
		}
		fmt.Fprintln(os.Stdout, line)
	}
}
