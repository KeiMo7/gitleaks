package detect

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zricethezav/gitleaks/v8/report"
)

// IsNew reports whether finding is not represented in baseline.
//
// Matching is layered:
//
//  1. The historical full-field comparison is preserved verbatim, so every
//     existing JSON baseline keeps exactly the same suppression result.
//  2. A structural overlay additionally accepts entries that differ only in
//     format-specific or cosmetic fields (descriptions, tags, entropy noise,
//     date encodings, missing commit metadata, path shape and masking).
//
// The fingerprint itself is never regenerated here; the overlay only reads
// the already computed finding fingerprint.
func IsNew(finding report.Finding, redact uint, baseline []report.Finding) bool {
	for _, b := range baseline {
		if legacyBaselineEqual(finding, redact, b) {
			return false
		}
		if relation := Equivalent(finding, b, redact); relation == Same {
			return false
		}
		// Undecidable baseline entries never match anything and therefore do
		// not suppress the finding. Import-time validation surfaces them.
	}
	return true
}

// legacyBaselineEqual is the exact comparison used by gitleaks historically.
// It must remain byte-for-byte equivalent in behaviour to the previous IsNew
// body to preserve existing JSON baseline conclusions.
func legacyBaselineEqual(finding report.Finding, redact uint, b report.Finding) bool {
	// Explicitly testing each property as it gives significantly better performance in comparison to cmp.Equal(). Drawback is that
	// the code requires maintenance if/when the Finding struct changes
	return finding.RuleID == b.RuleID &&
		finding.Description == b.Description &&
		finding.StartLine == b.StartLine &&
		finding.EndLine == b.EndLine &&
		finding.StartColumn == b.StartColumn &&
		finding.EndColumn == b.EndColumn &&
		(redact > 0 || (finding.Match == b.Match && finding.Secret == b.Secret)) &&
		finding.File == b.File &&
		finding.Commit == b.Commit &&
		finding.Author == b.Author &&
		finding.Email == b.Email &&
		finding.Date == b.Date &&
		finding.Message == b.Message &&
		// Omit checking finding.Fingerprint - if the format of the fingerprint changes, the users will see unexpected behaviour
		finding.Entropy == b.Entropy
}

// LoadBaseline reads and parses a single baseline source. The format is
// detected from the content, not the file extension.
//
// The historical "could not open <path>" error text is preserved exactly.
func LoadBaseline(baselinePath string) ([]report.Finding, error) {
	bytes, err := os.ReadFile(baselinePath)
	if err != nil {
		return nil, fmt.Errorf("could not open %s", baselinePath)
	}

	previousFindings, err := parseBaselineNamed(baselinePath, bytes)
	if err != nil {
		// Parsers annotate the error with the source path; parsed entries may
		// be returned together with a validation aggregate.
		return previousFindings, err
	}

	return previousFindings, nil
}

// LoadBaselines loads and merges several baseline sources. Parsed entries are
// folded into an order-independent set; every unreadable/invalid source is
// reported, never silently skipped.
func LoadBaselines(baselinePaths []string) ([]report.Finding, error) {
	groups := make([][]report.Finding, 0, len(baselinePaths))
	var issues []error

	for _, p := range baselinePaths {
		findings, err := LoadBaseline(p)
		if findings != nil {
			groups = append(groups, findings)
		}
		if err != nil {
			var aggregate *BaselineImportError
			if errors.As(err, &aggregate) {
				for _, issue := range aggregate.Issues {
					issues = append(issues, issue)
				}
			} else {
				issues = append(issues, err)
			}
		}
	}

	merged := MergeBaselines(groups...)
	if len(issues) > 0 {
		return merged, &BaselineImportError{Issues: issues}
	}
	return merged, nil
}

// AddBaseline loads one baseline source and merges it into the detector.
// Calling it repeatedly combines multiple sources.
func (d *Detector) AddBaseline(baselinePath string, source string) error {
	if baselinePath == "" {
		d.baselinePath = ""
		return nil
	}

	absoluteSource, err := filepath.Abs(source)
	if err != nil {
		return err
	}

	absoluteBaseline, err := filepath.Abs(baselinePath)
	if err != nil {
		return err
	}

	relativeBaseline, err := filepath.Rel(absoluteSource, absoluteBaseline)
	if err != nil {
		return err
	}

	baseline, err := LoadBaseline(baselinePath)
	if err != nil {
		return err
	}

	d.baseline = MergeBaselines(d.baseline, baseline)
	d.baselinePath = relativeBaseline
	d.baselineAbs = append(d.baselineAbs, absoluteBaseline)
	if resolved, err := filepath.EvalSymlinks(absoluteBaseline); err == nil && resolved != absoluteBaseline {
		d.baselineAbs = append(d.baselineAbs, resolved)
	}

	return nil
}

// AddBaselines loads every baseline source as one merged set. All sources are
// attempted so the returned error can name every bad input.
func (d *Detector) AddBaselines(baselinePaths []string, source string) error {
	if len(baselinePaths) == 0 {
		return nil
	}

	var issues []error
	for _, p := range baselinePaths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		if err := d.AddBaseline(p, source); err != nil {
			var aggregate *BaselineImportError
			if errors.As(err, &aggregate) {
				issues = append(issues, aggregate.Issues...)
			} else {
				issues = append(issues, err)
			}
		}
	}

	if len(issues) > 0 {
		return &BaselineImportError{Issues: issues}
	}
	return nil
}

// isBaselineFragment reports whether a scanned fragment is one of the
// configured baseline files. Matching is robust to "./" prefixes, relative vs
// absolute invocation and symlink/target paths while staying exact about the
// file identity.
func (d *Detector) isBaselineFragment(filePath string) bool {
	if filePath == "" {
		return false
	}

	// Historical contract: direct string equality against d.baselinePath.
	if d.baselinePath != "" && filePath == d.baselinePath {
		return true
	}

	normalizedFragment := normalizePath(filePath)
	if d.baselinePath != "" && normalizedFragment != "" &&
		normalizedFragment == normalizePath(d.baselinePath) {
		return true
	}

	fragmentAbs, err := filepath.Abs(filePath)
	if err != nil {
		fragmentAbs = ""
	}
	var fragmentReal string
	if r, err := filepath.EvalSymlinks(filePath); err == nil {
		fragmentReal = r
	}

	for _, baseAbs := range d.baselineAbs {
		if fragmentAbs != "" {
			if baseAbs == fragmentAbs {
				return true
			}
			if normalizePath(baseAbs) == normalizePath(fragmentAbs) {
				return true
			}
		}
		if fragmentReal != "" {
			if baseAbs == fragmentReal {
				return true
			}
			if r, err := filepath.EvalSymlinks(baseAbs); err == nil && r == fragmentReal {
				return true
			}
		}
	}

	return false
}
