package detect

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/zricethezav/gitleaks/v8/report"
)

// BaselineError describes why a single baseline source could not be imported.
//
// Error text never contains finding values such as secrets or match snippets:
// at most the source path, format, entry index and structural field name are
// included.
type BaselineError struct {
	// Path is the baseline source path ("" when parsing in-memory bytes).
	Path string
	// Format is the detected/reported format: json, sarif, junit or csv.
	Format string
	// Entry is the 1-based report entry/result/testcase index, when known.
	Entry int
	// Field is the structural field the problem is tied to, when known.
	Field string
	// Line is the source line (CSV/XML), when known.
	Line int
	// Err is the underlying parser error.
	Err error
}

func (e *BaselineError) Error() string {
	var b strings.Builder
	if e.Path != "" {
		fmt.Fprintf(&b, "baseline %q", e.Path)
	} else {
		b.WriteString("baseline")
	}
	if e.Format != "" {
		fmt.Fprintf(&b, " (%s)", e.Format)
	}
	b.WriteString(": ")
	if e.Entry > 0 {
		fmt.Fprintf(&b, "entry #%d", e.Entry)
		if e.Field != "" {
			fmt.Fprintf(&b, " field %q", e.Field)
		}
		b.WriteString(" ")
	} else if e.Field != "" {
		fmt.Fprintf(&b, "field %q ", e.Field)
	}
	if e.Line > 0 {
		fmt.Fprintf(&b, "at line %d ", e.Line)
	}
	if e.Err != nil {
		b.WriteString(e.Err.Error())
	} else {
		b.WriteString("is undecidable: missing rule id and/or file location")
	}
	return b.String()
}

func (e *BaselineError) Unwrap() error { return e.Err }

// BaselineImportError aggregates every bad source in a multi-baseline load so
// the operator can fix all of them in one pass.
type BaselineImportError struct {
	Issues []error
}

func (e *BaselineImportError) Error() string {
	parts := make([]string, 0, len(e.Issues))
	for _, issue := range e.Issues {
		parts = append(parts, issue.Error())
	}
	return strings.Join(parts, "; ")
}

func (e *BaselineImportError) Unwrap() []error {
	return e.Issues
}

// ParseBaseline sniffs the report format from its CONTENT and returns the
// contained findings. Supported shapes are:
//
//   - gitleaks JSON array reports,
//   - comma separated table (CSV) reports,
//   - SARIF 2.1.0 static analysis exchange reports,
//   - gitleaks/standard JUnit XML reports.
//
// Zero-byte/whitespace-only input is accepted as an empty baseline because
// that is exactly what gitleaks' CSV reporter emits for zero findings.
// Non-empty text that matches none of the supported shapes is rejected
// instead of silently becoming an empty baseline.
func ParseBaseline(data []byte) ([]report.Finding, error) {
	return parseBaselineNamed("", data)
}

func parseBaselineNamed(origin string, data []byte) ([]report.Finding, error) {
	// Tolerate a UTF-8 BOM produced by some editors.
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})

	if len(bytes.TrimSpace(data)) == 0 {
		return []report.Finding{}, nil
	}

	first := firstNonSpaceByte(data)
	switch first {
	case '[':
		return parseJSONArray(origin, data)
	case '{':
		return parseJSONObject(origin, data)
	case '<':
		return parseJUnit(origin, data)
	default:
		return parseCSV(origin, data)
	}
}

func firstNonSpaceByte(data []byte) byte {
	for _, b := range data {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			return b
		}
	}
	return 0
}

// finalizeEntries applies fingerprint enrichment and decidability validation.
// It returns the usable entries plus an aggregate error listing every
// undecidable entry. Entries are returned even when issues are reported so
// callers can keep an auditable record.
func finalizeEntries(origin, format string, raw []report.Finding) ([]report.Finding, error) {
	out := make([]report.Finding, 0, len(raw))
	var issues []error

	for i := range raw {
		f := raw[i]
		enrichFromFingerprint(&f)
		if !Decidable(f) {
			issues = append(issues, &BaselineError{
				Path:   origin,
				Format: format,
				Entry:  i + 1,
				Field:  requiredLocationField(f),
			})
		}
		out = append(out, f)
	}

	if len(issues) > 0 {
		return out, &BaselineImportError{Issues: issues}
	}
	return out, nil
}

func requiredLocationField(f report.Finding) string {
	switch {
	case strings.TrimSpace(f.RuleID) == "":
		return "RuleID"
	case strings.TrimSpace(f.File) == "" && strings.TrimSpace(f.Fingerprint) == "":
		return "File"
	case strings.TrimSpace(f.File) == "":
		return "File/Fingerprint"
	default:
		return "location"
	}
}

func enrichFromFingerprint(f *report.Finding) {
	if f.Fingerprint == "" {
		return
	}
	fp, ok := parseFingerprint(f.Fingerprint)
	if !ok {
		return
	}
	if f.File == "" {
		f.File = fp.file
	}
	if f.RuleID == "" {
		f.RuleID = fp.ruleID
	}
	if f.StartLine == 0 {
		f.StartLine = fp.line
	}
	if f.Commit == "" && fp.commit != "" {
		f.Commit = fp.commit
	}
}

// --- JSON array -------------------------------------------------------------

func parseJSONArray(origin string, data []byte) ([]report.Finding, error) {
	var raws []json.RawMessage
	if err := json.Unmarshal(data, &raws); err != nil {
		return nil, jsonBaselineError(origin, "json", 0, err, data)
	}

	findings := make([]report.Finding, 0, len(raws))
	for i, raw := range raws {
		var f report.Finding
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, jsonBaselineError(origin, "json", i+1, err, raw)
		}
		findings = append(findings, f)
	}
	return finalizeEntries(origin, "json", findings)
}

// --- JSON object: SARIF vs unknown -----------------------------------------

func parseJSONObject(origin string, data []byte) ([]report.Finding, error) {
	// Route SARIF-shaped documents directly so truncation errors keep the
	// "sarif" format label.
	head := bytes.ToLower(data)
	if bytes.Contains(head, []byte(`"runs"`)) || bytes.Contains(head, []byte("sarif")) {
		return parseSARIF(origin, data)
	}

	var probe struct {
		Schema  string            `json:"$schema"`
		Version string            `json:"version"`
		Runs    []json.RawMessage `json:"runs"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, jsonBaselineError(origin, "json", 0, err, data)
	}

	looksSarif := len(probe.Runs) > 0 ||
		strings.Contains(strings.ToLower(probe.Schema), "sarif") ||
		probe.Version != ""
	if !looksSarif {
		return nil, &BaselineError{
			Path:   origin,
			Format: "json",
			Err:    errors.New("unrecognized JSON object report (expected a gitleaks JSON array or SARIF document); custom-template output cannot be used as a baseline"),
		}
	}
	return parseSARIF(origin, data)
}

func parseSARIF(origin string, data []byte) ([]report.Finding, error) {
	var doc struct {
		Runs []json.RawMessage `json:"runs"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, jsonBaselineError(origin, "sarif", 0, err, data)
	}

	var findings []report.Finding
	for runIdx, runRaw := range doc.Runs {
		var run struct {
			Tool struct {
				Driver struct {
					Rules []report.Rules `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []json.RawMessage `json:"results"`
		}
		if err := json.Unmarshal(runRaw, &run); err != nil {
			return nil, jsonBaselineError(origin, "sarif", 0, err, runRaw)
		}
		descriptions := map[string]string{}
		for _, rule := range run.Tool.Driver.Rules {
			descriptions[rule.ID] = rule.Description.Text
		}

		for resIdx, resRaw := range run.Results {
			var r report.Results
			if err := json.Unmarshal(resRaw, &r); err != nil {
				return nil, jsonBaselineError(origin, "sarif", resIdx+1, err, resRaw)
			}
			f := sarifResultToFinding(r)
			if f.Description == "" {
				f.Description = descriptions[f.RuleID]
			}
			_ = runIdx
			findings = append(findings, f)
		}
	}

	return finalizeEntries(origin, "sarif", findings)
}

func sarifResultToFinding(r report.Results) report.Finding {
	f := report.Finding{
		RuleID:  r.RuleId,
		Commit:  r.PartialFingerPrints.CommitSha,
		Email:   r.PartialFingerPrints.Email,
		Author:  r.PartialFingerPrints.Author,
		Date:    r.PartialFingerPrints.Date,
		Message: r.PartialFingerPrints.CommitMessage,
		Tags:    r.Properties.Tags,
	}
	if len(r.Locations) > 0 {
		loc := r.Locations[0].PhysicalLocation
		f.File = loc.ArtifactLocation.URI
		f.StartLine = loc.Region.StartLine
		f.EndLine = loc.Region.EndLine
		f.StartColumn = loc.Region.StartColumn
		f.EndColumn = loc.Region.EndColumn
		// The gitleaks SARIF reporter stores the secret in the snippet.
		f.Secret = loc.Region.Snippet.Text
	}
	return f
}

// jsonBaselineError converts a JSON parser error into a located, secret-free
// BaselineError including line/column and a best-effort field path.
func jsonBaselineError(origin, format string, entry int, err error, payload []byte) error {
	be := &BaselineError{Path: origin, Format: format, Entry: entry, Err: err}

	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syntaxErr):
		be.Line, be.Field = jsonErrorContext(payload, syntaxErr.Offset)
		be.Err = fmt.Errorf("truncated or invalid %s document: %w", strings.ToUpper(format), err)
	case errors.As(err, &typeErr):
		be.Field = typeErr.Field
		if typeErr.Offset > 0 {
			be.Line, _ = lineColumn(payload, typeErr.Offset)
		}
		be.Err = fmt.Errorf("incompatible field type %q: %w", typeErr.Value, err)
	}
	if be.Field == "" {
		if _, field := jsonErrorContext(payload, -1); field != "" {
			be.Field = field
		}
	}
	return be
}

// jsonErrorContext returns the line number and best-effort enclosing JSON
// field path around offset.
func jsonErrorContext(data []byte, offset int64) (int, string) {
	if offset > 0 {
		line, _ := lineColumn(data, offset)
		path := jsonPathAt(data, offset)
		return line, path
	}
	return 0, jsonPathAt(data, int64(len(data)))
}

func lineColumn(data []byte, offset int64) (int, int) {
	if offset <= 0 {
		return 1, 1
	}
	if int(offset) > len(data) {
		offset = int64(len(data))
	}
	line := 1
	lastNL := int64(-1)
	for i := int64(0); i < offset; i++ {
		if data[i] == '\n' {
			line++
			lastNL = i
		}
	}
	col := int(offset) - int(lastNL)
	return line, col
}

// jsonPathAt makes a best-effort attempt to describe the object/field path
// immediately preceding offset (e.g. runs[0].results[2].ruleId).
func jsonPathAt(data []byte, offset int64) string {
	if offset <= 0 || int(offset) > len(data) {
		offset = int64(len(data))
	}

	type frame struct {
		key   string
		arr   bool
		index int
	}
	var stack []*frame
	beforeValue := func() {
		if n := len(stack); n > 0 && stack[n-1].arr {
			stack[n-1].index++
		}
	}

	dec := json.NewDecoder(bytes.NewReader(data[:offset]))
	for {
		t, err := dec.Token()
		if err != nil {
			break
		}
		switch tok := t.(type) {
		case json.Delim:
			switch tok {
			case '{':
				beforeValue()
				stack = append(stack, &frame{})
			case '[':
				beforeValue()
				stack = append(stack, &frame{arr: true, index: -1})
			case '}', ']':
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
			}
		case string:
			pos := int(dec.InputOffset())
			rest := bytes.TrimLeft(data[minInt(pos, len(data)):], " \t\r\n")
			if len(rest) > 0 && rest[0] == ':' && len(stack) > 0 && !stack[len(stack)-1].arr {
				stack[len(stack)-1].key = tok
			} else {
				beforeValue()
			}
		default:
			beforeValue()
		}
	}

	var b strings.Builder
	for _, f := range stack {
		switch {
		case f.arr:
			fmt.Fprintf(&b, "[%d]", f.index)
		case f.key != "":
			if b.Len() > 0 {
				b.WriteByte('.')
			}
			b.WriteString(f.key)
		}
	}
	return b.String()
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// --- JUnit XML --------------------------------------------------------------

func parseJUnit(origin string, data []byte) ([]report.Finding, error) {
	// Local DTOs with explicit element tags: the report package structs are
	// tuned for marshaling and their repeated field is not unmarshal-tagged.
	type failure struct {
		Data    string `xml:",chardata"`
		Message string `xml:"message,attr"`
		Type    string `xml:"type,attr"`
	}
	type testCase struct {
		Classname string  `xml:"classname,attr"`
		File      string  `xml:"file,attr"`
		Name      string  `xml:"name,attr"`
		Failure   failure `xml:"failure"`
	}
	type testSuite struct {
		TestCases []testCase `xml:"testcase"`
	}
	type testSuites struct {
		XMLName    xml.Name    `xml:"testsuites"`
		TestSuites []testSuite `xml:"testsuite"`
	}

	var cases []testCase

	var suites testSuites
	if err := xml.Unmarshal(data, &suites); err != nil {
		var single testSuite
		if err2 := xml.Unmarshal(data, &single); err2 != nil {
			var sx *xml.SyntaxError
			if errors.As(err, &sx) {
				return nil, &BaselineError{Path: origin, Format: "junit", Line: sx.Line, Err: fmt.Errorf("truncated or invalid JUnit XML: %w", err)}
			}
			return nil, &BaselineError{Path: origin, Format: "junit", Err: fmt.Errorf("invalid JUnit XML: %w", err)}
		}
		cases = append(cases, single.TestCases...)
	} else {
		for _, s := range suites.TestSuites {
			cases = append(cases, s.TestCases...)
		}
	}

	findings := make([]report.Finding, 0, len(cases))
	for _, tc := range cases {
		f := junitCaseToFinding(tc.File, tc.Name, tc.Classname, tc.Failure.Message, tc.Failure.Type, tc.Failure.Data)
		findings = append(findings, f)
	}
	return finalizeEntries(origin, "junit", findings)
}

func junitCaseToFinding(file, name, classname, failMessage, failType, charData string) report.Finding {
	// Preferred path: gitleaks embeds the full Finding as failure chardata.
	if raw := strings.TrimSpace(charData); raw != "" {
		var f report.Finding
		if err := json.Unmarshal([]byte(raw), &f); err == nil {
			return f
		}
	}

	// Fallback for generic JUnit producers: recover coordinates from
	// attributes and the human-readable message.
	msg := failMessage
	if msg == "" {
		msg = name
	}
	f := report.Finding{
		File:        file,
		Description: firstNonEmpty(failType, classname),
	}
	if id, msgFile, line := parseGitleaksMessage(msg); id != "" {
		f.RuleID = id
		if f.File == "" {
			f.File = msgFile
		}
		f.StartLine = line
	}
	return f
}

// parseGitleaksMessage extracts rule id, file and line from:
//
//	<rule> has detected a secret in file <file>, line <n>[, at commit <sha>].
func parseGitleaksMessage(msg string) (ruleID, file string, line int) {
	idx := strings.Index(msg, " has detected")
	if idx < 0 {
		return "", "", 0
	}
	ruleID = strings.TrimSpace(msg[:idx])

	if fi := strings.Index(msg, " in file "); fi >= 0 {
		rest := msg[fi+len(" in file "):]
		if ci := strings.Index(rest, ", line "); ci >= 0 {
			file = rest[:ci]
			linePart := rest[ci+len(", line "):]
			if dot := strings.IndexAny(linePart, ".,"); dot >= 0 {
				linePart = linePart[:dot]
			}
			line, _ = strconv.Atoi(strings.TrimSpace(linePart))
		}
	}
	return ruleID, file, line
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// --- CSV --------------------------------------------------------------------

// csvHeaderAliases maps normalized header names to Finding field names.
var csvHeaderAliases = map[string]string{
	"ruleid":      "RuleID",
	"description": "Description",
	"commit":      "Commit",
	"file":        "File",
	"symlinkfile": "SymlinkFile",
	"secret":      "Secret",
	"match":       "Match",
	"startline":   "StartLine",
	"endline":     "EndLine",
	"startcolumn": "StartColumn",
	"endcolumn":   "EndColumn",
	"author":      "Author",
	"message":     "Message",
	"date":        "Date",
	"email":       "Email",
	"fingerprint": "Fingerprint",
	"tags":        "Tags",
	"link":        "Link",
	"entropy":     "Entropy",
}

func parseCSV(origin string, data []byte) ([]report.Finding, error) {
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = -1 // tolerate header/record length drift
	r.LazyQuotes = false
	r.TrimLeadingSpace = true

	header, err := r.Read()
	if errors.Is(err, io.EOF) {
		return []report.Finding{}, nil
	}
	if err != nil {
		return nil, csvError(origin, 0, err)
	}

	index := map[string]int{}
	for i, h := range header {
		key := strings.ToLower(strings.TrimSpace(h))
		if name, ok := csvHeaderAliases[key]; ok {
			index[name] = i
		}
	}

	_, hasRule := index["RuleID"]
	_, hasFile := index["File"]
	_, hasFP := index["Fingerprint"]
	if !hasRule || (!hasFile && !hasFP) {
		return nil, &BaselineError{
			Path:   origin,
			Format: "csv",
			Line:   1,
			Err:    errors.New("unrecognized comma-separated report: header must contain at least RuleID and File/Fingerprint columns; custom-template output cannot be used as a baseline"),
		}
	}

	get := func(rec []string, field string) string {
		i, ok := index[field]
		if !ok || i >= len(rec) {
			return ""
		}
		return rec[i]
	}

	var findings []report.Finding
	rowNum := 1
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			line := rowNum + 1
			var pe *csv.ParseError
			if errors.As(err, &pe) {
				line = pe.Line
			}
			return nil, csvError(origin, line, err)
		}
		rowNum++

		if len(rec) == 0 || (len(rec) == 1 && strings.TrimSpace(rec[0]) == "") {
			continue
		}

		f := report.Finding{
			RuleID:      get(rec, "RuleID"),
			Description: get(rec, "Description"),
			Commit:      get(rec, "Commit"),
			File:        get(rec, "File"),
			SymlinkFile: get(rec, "SymlinkFile"),
			Secret:      get(rec, "Secret"),
			Match:       get(rec, "Match"),
			Author:      get(rec, "Author"),
			Message:     get(rec, "Message"),
			Date:        get(rec, "Date"),
			Email:       get(rec, "Email"),
			Fingerprint: get(rec, "Fingerprint"),
			Link:        get(rec, "Link"),
			Tags:        splitTags(get(rec, "Tags")),
			StartLine:   atoiLenient(get(rec, "StartLine")),
			EndLine:     atoiLenient(get(rec, "EndLine")),
			StartColumn: atoiLenient(get(rec, "StartColumn")),
			EndColumn:   atoiLenient(get(rec, "EndColumn")),
		}
		if v := get(rec, "Entropy"); v != "" {
			if f64, err := strconv.ParseFloat(v, 32); err == nil {
				f.Entropy = float32(f64)
			}
		}
		findings = append(findings, f)
	}

	return finalizeEntries(origin, "csv", findings)
}

func splitTags(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	// CSV reporter joins tags with spaces; tags themselves do not contain
	// spaces in gitleaks rule definitions.
	return strings.Fields(v)
}

func atoiLenient(v string) int {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	// Accept "32" and a few common float encodings without failing an import.
	if n, err := strconv.Atoi(v); err == nil {
		return n
	}
	if f, err := strconv.ParseFloat(v, 64); err == nil {
		return int(f)
	}
	return 0
}

func csvError(origin string, line int, err error) error {
	var pe *csv.ParseError
	if errors.As(err, &pe) {
		if line == 0 {
			line = pe.Line
		}
		return &BaselineError{Path: origin, Format: "csv", Line: line, Err: fmt.Errorf("invalid comma-separated report: %w", pe.Err)}
	}
	return &BaselineError{Path: origin, Format: "csv", Line: line, Err: err}
}
