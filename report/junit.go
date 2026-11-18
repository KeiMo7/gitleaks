package report

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
)

type JunitReporter struct {
}

var _ Reporter = (*JunitReporter)(nil)

func (r *JunitReporter) Write(w io.WriteCloser, findings []Finding) error {
	testSuites := TestSuites{
		TestSuites: getTestSuites(findings),
	}

	io.WriteString(w, xml.Header)
	encoder := xml.NewEncoder(w)
	encoder.Indent("", "\t")
	return encoder.Encode(testSuites)
}

func getTestSuites(findings []Finding) []TestSuite {
	failureCount := 0
	for _, finding := range findings {
		if finding.Decision == "" || finding.Decision == DecisionUnset || finding.Decision == DecisionBlocking {
			failureCount++
		}
	}
	return []TestSuite{
		{
			Failures:  strconv.Itoa(failureCount),
			Name:      "gitleaks",
			Tests:     strconv.Itoa(len(findings)),
			TestCases: getTestCases(findings),
			Time:      "",
		},
	}
}

func getTestCases(findings []Finding) []TestCase {
	testCases := []TestCase{}
	for _, f := range findings {
		testCase := TestCase{
			Classname: f.Description,
			File:      f.File,
			Name:      getMessage(f),
			Time:      "",
		}
		// With level gating enabled, only blocking findings are JUnit
		// failures; reported/exempted findings stay present as passing cases.
		if f.Decision == "" || f.Decision == DecisionUnset || f.Decision == DecisionBlocking {
			testCase.Failure = getFailure(f)
		}
		testCases = append(testCases, testCase)
	}
	return testCases
}

func getFailure(f Finding) Failure {
	return Failure{
		Data:    getData(f),
		Message: getMessage(f),
		Type:    f.Description,
	}
}

func getData(f Finding) string {
	data, err := json.MarshalIndent(f, "", "\t")
	if err != nil {
		fmt.Println(err)
		return ""
	}
	return string(data)
}

func getMessage(f Finding) string {
	level := ""
	if f.Severity != "" {
		level = fmt.Sprintf(" (severity=%s confidence=%s decision=%s)", f.Severity, f.Confidence, f.Decision)
	}
	if f.Commit == "" {
		return fmt.Sprintf("%s has detected a secret in file %s, line %s.%s", f.RuleID, f.File, strconv.Itoa(f.StartLine), level)
	}

	return fmt.Sprintf("%s has detected a secret in file %s, line %s, at commit %s.%s", f.RuleID, f.File, strconv.Itoa(f.StartLine), f.Commit, level)
}

type TestSuites struct {
	XMLName    xml.Name `xml:"testsuites"`
	TestSuites []TestSuite
}

type TestSuite struct {
	XMLName   xml.Name   `xml:"testsuite"`
	Failures  string     `xml:"failures,attr"`
	Name      string     `xml:"name,attr"`
	Tests     string     `xml:"tests,attr"`
	TestCases []TestCase `xml:"testcase"`
	Time      string     `xml:"time,attr"`
}

type TestCase struct {
	XMLName   xml.Name `xml:"testcase"`
	Classname string   `xml:"classname,attr"`
	Failure   Failure  `xml:"failure"`
	File      string   `xml:"file,attr"`
	Name      string   `xml:"name,attr"`
	Time      string   `xml:"time,attr"`
}

type Failure struct {
	XMLName xml.Name `xml:"failure"`
	Data    string   `xml:",chardata"`
	Message string   `xml:"message,attr"`
	Type    string   `xml:"type,attr"`
}
