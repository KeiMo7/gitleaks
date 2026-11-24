package report

import (
	"encoding/csv"
	"io"
	"strconv"
	"strings"

	"github.com/zricethezav/gitleaks/v8/lifecycle"
)

type CsvReporter struct {
}

var _ Reporter = (*CsvReporter)(nil)

func (r *CsvReporter) Write(w io.WriteCloser, findings []Finding) error {
	if len(findings) == 0 {
		return nil
	}

	var (
		cw  = csv.NewWriter(w)
		err error
	)
	columns := []string{"RuleID",
		"Commit",
		"File",
		"SymlinkFile",
		"Secret",
		"Match",
		"StartLine",
		"EndLine",
		"StartColumn",
		"EndColumn",
		"Author",
		"Message",
		"Date",
		"Email",
		"Fingerprint",
		"Tags",
	}
	// A miserable attempt at "omitempty" so tests don't yell at me.
	if findings[0].Link != "" {
		columns = append(columns, "Link")
	}
	// Lifecycle columns are appended after every existing column so existing
	// consumers keep their column positions. They appear only when lifecycle
	// analysis was enabled.
	withLifecycle := false
	for i := range findings {
		if findings[i].Lifecycle != nil {
			withLifecycle = true
			break
		}
	}
	if withLifecycle {
		columns = append(columns, "LifecycleStatus", "LifecycleFirstSeenCommit", "LifecycleFirstSeenDate", "LifecycleLastSeenCommit", "LifecycleLastSeenDate", "LifecycleMergedBranches", "LifecycleHistoricalBranches")
	}

	if err = cw.Write(columns); err != nil {
		return err
	}
	for _, f := range findings {
		row := []string{f.RuleID,
			f.Commit,
			f.File,
			f.SymlinkFile,
			f.Secret,
			f.Match,
			strconv.Itoa(f.StartLine),
			strconv.Itoa(f.EndLine),
			strconv.Itoa(f.StartColumn),
			strconv.Itoa(f.EndColumn),
			f.Author,
			f.Message,
			f.Date,
			f.Email,
			f.Fingerprint,
			strings.Join(f.Tags, " "),
		}
		if findings[0].Link != "" {
			row = append(row, f.Link)
		}
		if withLifecycle {
			row = append(row, lifecycleColumns(f.Lifecycle)...)
		}

		if err = cw.Write(row); err != nil {
			return err
		}
	}

	cw.Flush()
	return cw.Error()
}

// lifecycleColumns renders a lifecycle summary as the appended CSV cells.
func lifecycleColumns(info *lifecycle.Info) []string {
	if info == nil {
		return []string{"", "", "", "", "", "", ""}
	}
	firstCommit, firstDate, lastCommit, lastDate := "", "", "", ""
	if info.FirstSeen != nil {
		firstCommit = info.FirstSeen.Commit
		firstDate = info.FirstSeen.Date
	}
	if info.LastSeen != nil {
		lastCommit = info.LastSeen.Commit
		lastDate = info.LastSeen.Date
	}
	return []string{
		string(info.Status),
		firstCommit,
		firstDate,
		lastCommit,
		lastDate,
		strconv.Itoa(info.MergedBranches),
		strconv.Itoa(info.HistoricalBranches),
	}
}
