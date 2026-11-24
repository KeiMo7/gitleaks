package lifecycle_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/zricethezav/gitleaks/v8/lifecycle"
)

var (
	buildOnce sync.Once
	binPath   string
	buildErr  error
	repoRoot  string
)

// gitleaksBinary builds the CLI once per test binary so the tests exercise the
// real command surface (flags, exit codes, reporters) instead of internals.
func gitleaksBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		root, err := moduleRoot()
		if err != nil {
			buildErr = err
			return
		}
		repoRoot = root
		dir, err := os.MkdirTemp("", "gitleaks-e2e-bin-")
		if err != nil {
			buildErr = err
			return
		}
		binPath = filepath.Join(dir, "gitleaks")
		cmd := exec.Command("go", "build", "-o", binPath, ".")
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err != nil {
			buildErr = fmt.Errorf("build gitleaks: %w\n%s", err, out)
		}
	})
	if buildErr != nil {
		t.Fatalf("could not build gitleaks: %v", buildErr)
	}
	return binPath
}

func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found above %s", dir)
		}
		dir = parent
	}
}

// testConfig is deliberately tiny: one literal token rule plus a second rule
// that matches the same token so "same digest, different rule" can be checked.
const testConfig = `title = "lifecycle e2e"
[[rules]]
    id = "lit-token"
    description = "Literal test token"
    # \s* lets the same value be detected when it is split over a line break,
    # which canonicalization then normalizes away.
    regex = '''LCK_[A-Z0-9]{4}\s*[A-Z0-9]{4}'''
    keywords = ["LCK_"]
    tags = ["test"]

[[rules]]
    id = "alt-token"
    description = "Alternate literal test token"
    regex = '''LCK_(?:ALPHA|BETA)[A-Z0-9]{3}'''
    keywords = ["LCK_"]
    tags = ["test", "alt"]
`

type repoFixture struct {
	t   *testing.T
	dir string
	env []string
	cfg string
}

func newRepo(t *testing.T) *repoFixture {
	t.Helper()
	dir := t.TempDir()
	r := &repoFixture{t: t, dir: dir}

	cfgPath := filepath.Join(t.TempDir(), "gitleaks.toml")
	if err := os.WriteFile(cfgPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	r.cfg = cfgPath
	r.env = append(os.Environ(),
		"GIT_AUTHOR_NAME=E2E",
		"GIT_AUTHOR_EMAIL=e2e@example.com",
		"GIT_COMMITTER_NAME=E2E",
		"GIT_COMMITTER_EMAIL=e2e@example.com",
	)
	r.git("init", "-q", "-b", "main")
	return r
}

// git runs a git command with a fixed identity and returns trimmed stdout.
func (r *repoFixture) git(args ...string) string {
	r.t.Helper()
	cmd := exec.Command("git", append([]string{"-C", r.dir}, args...)...)
	cmd.Env = r.env
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

type commitSpec struct {
	date string // RFC3339
	msg  string
}

func (r *repoFixture) commit(spec commitSpec, files map[string]string, removals ...string) string {
	r.t.Helper()
	for path, content := range files {
		full := filepath.Join(r.dir, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			r.t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			r.t.Fatal(err)
		}
	}
	for _, path := range removals {
		r.git("rm", "-q", "--", path)
	}

	r.env = setEnv(r.env, "GIT_AUTHOR_DATE", spec.date)
	r.env = setEnv(r.env, "GIT_COMMITTER_DATE", spec.date)
	r.git("add", "-A")
	r.git("commit", "-q", "--allow-empty", "-m", spec.msg)
	return r.git("rev-parse", "HEAD")
}

func setEnv(env []string, key, value string) []string {
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		if strings.HasPrefix(kv, key+"=") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, key+"="+value)
}

type runResult struct {
	stdout   string
	stderr   string
	exitCode int
}

func runGitleaks(t *testing.T, args ...string) runResult {
	t.Helper()
	bin := gitleaksBinary(t)
	cmd := exec.Command(bin, args...)
	// Scanning runs concurrently; lifecycle-enabled runs sort their findings
	// before reporting, so byte-for-byte assertions should not need a pinned
	// scheduler. Keep a modest cap to limit test resource use.
	cmd.Env = append(os.Environ(), "GOMAXPROCS=4")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if ok := asExitError(err, &exitErr); ok {
			code = exitErr.ExitCode()
		} else {
			t.Fatalf("running gitleaks %v: %v\n%s", args, err, stderr.String())
		}
	}
	return runResult{stdout: stdout.String(), stderr: stderr.String(), exitCode: code}
}

func asExitError(err error, target **exec.ExitError) bool {
	if e, ok := err.(*exec.ExitError); ok {
		*target = e
		return true
	}
	return false
}

// primaryReport is the raw primary report produced by a scan.
type primaryReport struct {
	raw string
}

// scanGit runs a lifecycle-enabled git scan and returns the lifecycle report.

func scanGit(t *testing.T, repo string, extra ...string) (lifecycle.Report, string, primaryReport, runResult) {
	t.Helper()
	outDir := t.TempDir()
	lcPath := filepath.Join(outDir, "lifecycle.json")
	reportPath := filepath.Join(outDir, "findings.json")
	args := append([]string{
		"git", repo,
		"--config", filepath.Join(repo, ".gitleaks.toml"),
		"--report-path", reportPath,
		"--report-format", "json",
		"--lifecycle",
		"--lifecycle-report-path", lcPath,
		"--log-level", "error",
		"--no-banner",
	}, extra...)

	// Keep the temp config next to the repo so the scan picks it up exactly
	// like a normal project config.
	if _, err := os.Stat(filepath.Join(repo, ".gitleaks.toml")); err != nil {
		t.Fatalf("repo config missing: %v", err)
	}

	res := runGitleaks(t, args...)
	raw, err := os.ReadFile(lcPath)
	if err != nil {
		t.Fatalf("lifecycle report missing (exit %d)\nstdout:\n%s\nstderr:\n%s", res.exitCode, res.stdout, res.stderr)
	}
	return mustParse(t, raw), string(raw), primaryReport{raw: mustRead(t, reportPath)}, res
}

// jsonKeyOrder extracts top-level object keys of the first array element in
// document order (encoding/json preserves map iteration order only through
// raw scanning, so this decodes tokens).
func jsonKeyOrder(t *testing.T, raw []byte) []string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		t.Fatal(err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		t.Fatalf("expected array, got %v", tok)
	}
	if _, err := dec.Token(); err != nil { // "{"
		t.Fatal(err)
	}
	var keys []string
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		switch tt := tok.(type) {
		case json.Delim:
			if tt == '{' || tt == '[' {
				depth++
			} else {
				depth--
			}
			if depth < 0 {
				return keys
			}
		case string:
			if depth == 0 {
				keys = append(keys, tt)
				// Skip the value.
				var skip json.RawMessage
				if err := dec.Decode(&skip); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// parseReport unmarshals a lifecycle document.
func parseReport(raw []byte) (lifecycle.Report, error) {
	var rep lifecycle.Report
	err := json.Unmarshal(raw, &rep)
	return rep, err
}

// execGit runs git outside a fixture (e.g. clone).
func execGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=E2E", "GIT_AUTHOR_EMAIL=e2e@example.com",
		"GIT_COMMITTER_NAME=E2E", "GIT_COMMITTER_EMAIL=e2e@example.com",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func writeConfig(t *testing.T, repo string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(repo, ".gitleaks.toml"), []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
}

func pickEntries(rep lifecycle.Report, ruleID string) []lifecycle.Entry {
	var out []lifecycle.Entry
	for _, e := range rep.Secrets {
		if e.RuleID == ruleID {
			out = append(out, e)
		}
	}
	return out
}

func findByFirstCommit(entries []lifecycle.Entry, commit string) *lifecycle.Entry {
	for i := range entries {
		if entries[i].FirstSeen != nil && entries[i].FirstSeen.Commit == commit {
			return &entries[i]
		}
	}
	return nil
}

func mustParse(t *testing.T, raw []byte) lifecycle.Report {
	t.Helper()
	rep, err := parseReport(raw)
	if err != nil {
		t.Fatalf("invalid lifecycle json: %v\n%s", err, raw)
	}
	return rep
}

// canonicalWrapper returns a base64 form of the secret for the encoding test.
func canonicalWrapper(secret string) (string, error) {
	if len(secret) == 0 {
		return "", fmt.Errorf("empty secret")
	}
	return base64.StdEncoding.EncodeToString([]byte(secret)), nil
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
