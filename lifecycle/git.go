package lifecycle

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Repo performs read-only git queries for the lifecycle analysis.
//
// Every query is bounded by ctx (and CommandTimeout) and every failure is
// recorded in Diagnostics rather than aborting the scan. Callers must treat an
// error as "conclusion unavailable", never as "secret absent".
type Repo struct {
	dir string

	mu   sync.Mutex
	diag Diagnostics

	// renameOnce guards the lazy rename table. renames maps a path to the
	// historical paths it was renamed from, and resetPath maps a current path
	// to its oldest known name.
	renameOnce sync.Once
	renames    map[string][]string
	resetPath  map[string]string
}

// NewRepo creates a Repo rooted at a work tree or repository directory.
func NewRepo(dir string) *Repo {
	return &Repo{dir: dir}
}

// Diagnostics returns a snapshot of degradation counters.
func (r *Repo) Diagnostics() Diagnostics {
	r.mu.Lock()
	defer r.mu.Unlock()
	d := r.diag
	d.SkippedRefs = append([]string(nil), d.SkippedRefs...)
	d.SkippedObjects = append([]string(nil), d.SkippedObjects...)
	d.Notes = append([]string(nil), d.Notes...)
	return d
}

func (r *Repo) note(msg string) {
	r.mu.Lock()
	r.diag.Notes = append(r.diag.Notes, msg)
	r.mu.Unlock()
}

func (r *Repo) bumpCommand(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		r.diag.CommandTimeouts++
		return
	}
	r.diag.CommandFailures++
}

func (r *Repo) addSkippedRef(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.diag.RefErrors++
	r.diag.SkippedRefs = append(r.diag.SkippedRefs, name)
}

func (r *Repo) addSkippedObject(obj string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.diag.ObjectErrors++
	if len(r.diag.SkippedObjects) < 100 {
		r.diag.SkippedObjects = append(r.diag.SkippedObjects, obj)
	}
}

// run executes git with a bounded timeout. Output is fully buffered.
func (r *Repo) run(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, CommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", r.dir}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		// Exit code 1 with no stderr is git's normal "no match" answer for
		// queries like `symbolic-ref --quiet` and `rev-parse --verify
		// --quiet`; it is not a degradation.
		if !isQuietMiss(err, stderr.Bytes()) {
			r.bumpCommand(err)
		}
		return nil, fmt.Errorf("git %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// isQuietMiss reports whether err is an exit-code-1 answer with no output,
// which git uses for "not found" in quiet queries.
func isQuietMiss(err error, stderr []byte) bool {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		return false
	}
	return len(bytes.TrimSpace(stderr)) == 0
}

// stream runs git and invokes fn with stdout line by line.
func (r *Repo) stream(ctx context.Context, args []string, fn func(line string) error) error {
	ctx, cancel := context.WithTimeout(ctx, CommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", r.dir}, args...)...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		r.bumpCommand(err)
		return err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		r.bumpCommand(err)
		return err
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var scanErr error
	for sc.Scan() {
		if err := fn(sc.Text()); err != nil {
			scanErr = err
			break
		}
	}
	if scanErr == nil {
		scanErr = sc.Err()
	}
	// Drain so the child is never blocked on a full pipe.
	_, _ = io.Copy(io.Discard, stdout)
	if err := cmd.Wait(); err != nil {
		r.bumpCommand(err)
		if scanErr == nil {
			scanErr = fmt.Errorf("git %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
		}
	}
	return scanErr
}

// IsRepository reports whether dir is inside a git repository (work tree or
// bare). The error collapses to false so directory scans still work.
func (r *Repo) IsRepository(ctx context.Context) bool {
	out, err := r.run(ctx, "rev-parse", "--git-dir")
	if err != nil {
		return false
	}
	return len(bytes.TrimSpace(out)) > 0
}

// IsRepositoryRoot reports whether dir is itself the top level of a work tree
// or a bare repository. Unlike IsRepository it does not accept a subdirectory
// of some unrelated enclosing repository, which would attribute history to the
// wrong project.
func (r *Repo) IsRepositoryRoot(ctx context.Context) bool {
	if !r.IsRepository(ctx) {
		return false
	}
	out, err := r.run(ctx, "rev-parse", "--show-toplevel")
	if err == nil {
		top := strings.TrimSpace(string(out))
		if top == "" {
			return true
		}
		return samePath(top, r.dir)
	}
	// Bare repositories have no work tree.
	if out, err := r.run(ctx, "rev-parse", "--is-bare-repository"); err == nil {
		return strings.TrimSpace(string(out)) == "true"
	}
	return false
}

func samePath(a, b string) bool {
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	if errA != nil || errB != nil {
		return a == b
	}
	if resolved, err := filepath.EvalSymlinks(absA); err == nil {
		absA = resolved
	}
	if resolved, err := filepath.EvalSymlinks(absB); err == nil {
		absB = resolved
	}
	return absA == absB
}

// Head returns the checked-out commit and its committer date.
func (r *Repo) Head(ctx context.Context) (sha, date string, err error) {
	out, err := r.run(ctx, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return "", "", err
	}
	sha = strings.TrimSpace(string(out))
	date, err = r.commitDate(ctx, sha)
	return sha, date, err
}

func (r *Repo) commitDate(ctx context.Context, sha string) (string, error) {
	out, err := r.run(ctx, "show", "-s", "--format=%cI", sha)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// SymbolicDefaultBranch resolves the default branch for local analysis:
// origin/HEAD, then the checked-out branch, then common branch names.
func (r *Repo) SymbolicDefaultBranch(ctx context.Context) (string, error) {
	if out, err := r.run(ctx, "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"); err == nil {
		name := strings.TrimSpace(string(out))
		name = strings.TrimPrefix(name, "origin/")
		if name != "" {
			return name, nil
		}
	}
	if out, err := r.run(ctx, "symbolic-ref", "--quiet", "--short", "HEAD"); err == nil {
		name := strings.TrimSpace(string(out))
		if name != "" {
			return name, nil
		}
	}
	for _, candidate := range []string{"main", "master", "trunk", "develop"} {
		if _, err := r.run(ctx, "rev-parse", "--verify", "--quiet", "refs/heads/"+candidate); err == nil {
			return candidate, nil
		}
	}
	return "", errors.New("could not determine default branch")
}

// ResolveCommit resolves any ref-ish name to a commit SHA.
func (r *Repo) ResolveCommit(ctx context.Context, ref string) (string, error) {
	out, err := r.run(ctx, "rev-parse", "--verify", "--quiet", ref+"^{commit}")
	if err != nil {
		return "", err
	}
	sha := strings.TrimSpace(string(out))
	if sha == "" {
		return "", fmt.Errorf("could not resolve %q", ref)
	}
	return sha, nil
}

// RootCommits returns the root commits of every reachable ref. They act as a
// stable repository identity even when remotes change.
func (r *Repo) RootCommits(ctx context.Context) []string {
	out, err := r.run(ctx, "rev-list", "--all", "--max-parents=0")
	if err != nil {
		return nil
	}
	var roots []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			roots = append(roots, line)
		}
	}
	sort.Strings(roots)
	return roots
}

// RemoteURL returns the first configured remote URL with credentials stripped.
func (r *Repo) RemoteURL(ctx context.Context) string {
	out, err := r.run(ctx, "config", "--get", "remote.origin.url")
	if err != nil {
		out, err = r.run(ctx, "config", "--get-regexp", `^remote\..*\.url$`)
		if err != nil {
			return ""
		}
		fields := strings.Fields(string(out))
		if len(fields) < 2 {
			return ""
		}
		return sanitizeRemoteURL(fields[1])
	}
	return sanitizeRemoteURL(strings.TrimSpace(string(out)))
}

// IsShallow reports whether the repository is a shallow clone.
func (r *Repo) IsShallow(ctx context.Context) bool {
	out, err := r.run(ctx, "rev-parse", "--is-shallow-repository")
	if err != nil {
		// Older git lacks the flag; a shallow file is still definitive.
		if _, statErr := r.run(ctx, "rev-parse", "--git-path", "shallow"); statErr != nil {
			return false
		}
		return false
	}
	return strings.TrimSpace(string(out)) == "true"
}

// ReplacedRefs lists configured ref replacements.
func (r *Repo) ReplacedRefs(ctx context.Context) []string {
	out, err := r.run(ctx, "for-each-ref", "--format=%(refname)", "refs/replace")
	if err != nil {
		return nil
	}
	var refs []string
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			refs = append(refs, line)
		}
	}
	return refs
}

// gitRef is a branch or tag with the commit it points at.
type gitRef struct {
	Name   string
	Type   string
	SHA    string
	Remote bool
}

// Refs lists local branches, remote-tracking branches and tags. Duplicate
// branch names (local vs origin) are collapsed onto the local ref.
func (r *Repo) Refs(ctx context.Context) ([]gitRef, error) {
	out, err := r.run(ctx, "for-each-ref",
		"--format=%(refname)%00%(objecttype)%00%(objectname)%00%(*objecttype)%00%(*objectname)",
		"refs/heads", "refs/remotes", "refs/tags")
	if err != nil {
		return nil, err
	}

	var all []gitRef

	for _, line := range strings.Split(string(out), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\x00")
		if len(fields) < 5 {
			continue
		}
		name, objType, objSHA, peeledType, peeledSHA := fields[0], fields[1], fields[2], fields[3], fields[4]

		ref := gitRef{SHA: objSHA}
		switch {
		case strings.HasPrefix(name, "refs/heads/"):
			ref.Name = strings.TrimPrefix(name, "refs/heads/")
			ref.Type = "branch"
		case strings.HasPrefix(name, "refs/remotes/"):
			short := strings.TrimPrefix(name, "refs/remotes/")
			if strings.HasSuffix(short, "/HEAD") {
				continue
			}
			ref.Name = short
			ref.Type = "branch"
			ref.Remote = true
		case strings.HasPrefix(name, "refs/tags/"):
			ref.Name = strings.TrimPrefix(name, "refs/tags/")
			ref.Type = "tag"
			// Annotated tags point at a tag object; use the peeled commit.
			if objType == "tag" && peeledType == "commit" {
				ref.SHA = peeledSHA
			}
			if objType != "commit" && peeledType != "commit" {
				continue
			}
		default:
			continue
		}
		all = append(all, ref)
	}

	// Collapse origin/<name> onto <name> when the local branch exists, and
	// keep only the first occurrence of each (type, name) pair.
	local := map[string]bool{}
	for _, ref := range all {
		if ref.Type == "branch" && !ref.Remote {
			local[ref.Name] = true
		}
	}

	var (
		refs []gitRef
		seen = map[string]bool{}
	)
	for _, ref := range all {
		if ref.Remote {
			short := ref.Name
			if i := strings.Index(short, "/"); i >= 0 {
				short = short[i+1:]
			}
			if local[short] {
				continue
			}
			ref.Name = short
		}
		key := ref.Type + "/" + ref.Name
		if seen[key] {
			continue
		}
		seen[key] = true
		refs = append(refs, ref)
	}

	sort.SliceStable(refs, func(i, j int) bool {
		if refs[i].Type != refs[j].Type {
			return refs[i].Type < refs[j].Type
		}
		return refs[i].Name < refs[j].Name
	})
	return refs, nil
}

// IsAncestor reports whether ancestor is reachable from descendant.
// It is the primitive for "has this ref been merged into the default branch".
func (r *Repo) IsAncestor(ctx context.Context, ancestor, descendant string) (bool, error) {
	if ancestor == "" || descendant == "" {
		return false, errors.New("empty commit for ancestry query")
	}
	cmdCtx, cancel := context.WithTimeout(ctx, CommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, "git", "-C", r.dir, "merge-base", "--is-ancestor", ancestor, descendant)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		// Exit code 1 is a definitive "no".
		return false, nil
	}
	r.bumpCommand(err)
	return false, fmt.Errorf("merge-base --is-ancestor %s %s: %w (%s)", ancestor, descendant, err, strings.TrimSpace(stderr.String()))
}

// CommitExists reports whether the object is present and parseable.
func (r *Repo) CommitExists(ctx context.Context, sha string) (bool, error) {
	_, err := r.run(ctx, "cat-file", "-e", sha+"^{commit}")
	if err != nil {
		if strings.Contains(err.Error(), "Not a valid object name") || strings.Contains(err.Error(), "could not get object info") {
			return false, err
		}
		return false, err
	}
	return true, nil
}

// CommitsInRef streams every commit reachable from ref into fn.
func (r *Repo) CommitsInRef(ctx context.Context, ref string, fn func(sha string) error) error {
	return r.stream(ctx, []string{"rev-list", ref}, fn)
}

// commitsSinceTipChanged returns the commits in ref that are not reachable
// from tip. Used when ref tips have diverged.
func (r *Repo) commitsSinceTipChanged(ctx context.Context, ref, tip string) (map[string]struct{}, error) {
	set := make(map[string]struct{})
	err := r.stream(ctx, []string{"rev-list", ref, "^" + tip}, func(sha string) error {
		set[sha] = struct{}{}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return set, nil
}

// renameResolver maps a path at a given commit to the oldest path it is known
// to have had. It performs rename detection once over the repository history
// and follows chains, so a rotate-in-place plus a later move still groups.
type renameResolver struct {
	// byNewPath holds all (old -> new) renames across history.
	byNewPath map[string][]string
}

func (r *Repo) loadRenames(ctx context.Context) {
	r.renameOnce.Do(func() {
		r.renames = map[string][]string{}
		r.resetPath = map[string]string{}

		// --name-status with -M gives "R<score>\told\tnew" lines. Restricting
		// the revision range to --all keeps this to reachable history.
		err := r.stream(ctx, []string{
			"log", "--all", "--name-status", "--format=", "-M", "--diff-filter=R", "-m",
			"--no-ext-diff", "--no-textconv", "--no-color",
		}, func(line string) error {
			if len(line) < 3 || line[0] != 'R' {
				return nil
			}
			parts := strings.Split(line, "\t")
			if len(parts) < 3 {
				return nil
			}
			oldPath, newPath := parts[1], parts[2]
			r.renames[newPath] = append(r.renames[newPath], oldPath)
			return nil
		})
		if err != nil {
			r.note("rename detection failed; renamed files are not grouped: " + err.Error())
			r.mu.Lock()
			r.diag.RefAnalysisLimited = true
			r.mu.Unlock()
		}

		// Flatten the chains deterministically. Cycles cannot normally exist
		// in git history, but guard against them anyway.
		for path := range r.renames {
			r.resetPath[path] = r.oldestPath(path, map[string]bool{})
		}
	})
}

// oldestPath follows rename edges back to the earliest known name. If a path
// has several historical sources (e.g. it was recreated after a delete), the
// first source in history order wins so the result is deterministic.
func (r *Repo) oldestPath(path string, seen map[string]bool) string {
	src, ok := r.renames[path]
	if !ok || len(src) == 0 || seen[path] {
		return path
	}
	seen[path] = true
	return r.oldestPath(src[0], seen)
}

// PathAtCommit returns the path history-aware identity for a finding.
//
// When renameColumns is set (the finding came from a new-side path), the
// oldest known name is returned so a rename or move does not split the
// secret across identifiers.
func (r *Repo) PathAtCommit(ctx context.Context, path string) string {
	r.loadRenames(ctx)
	if p, ok := r.resetPath[path]; ok && p != "" {
		return p
	}
	return path
}

// FileAtCommit reads a file from a commit. A missing or oversized object
// yields (nil, false) with diagnostics recorded; it is never fatal.
func (r *Repo) FileAtCommit(ctx context.Context, commit, path string, maxBytes int64) ([]byte, bool) {
	cmdCtx, cancel := context.WithTimeout(ctx, CommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, "git", "-C", r.dir, "cat-file", "blob", commit+":"+path)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		r.addSkippedObject(commit + ":" + path)
		return nil, false
	}
	if maxBytes > 0 && int64(stdout.Len()) > maxBytes {
		r.mu.Lock()
		r.diag.SkippedLargeBlobs++
		r.mu.Unlock()
		return nil, false
	}
	return stdout.Bytes(), true
}

// ListFilesAtCommit lists blob paths at a commit (recursive).
func (r *Repo) ListFilesAtCommit(ctx context.Context, commit string) ([]string, error) {
	out, err := r.run(ctx, "ls-tree", "-r", "-z", "--name-only", commit)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, p := range strings.Split(string(out), "\x00") {
		if p != "" {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	return paths, nil
}

// RepositoryInfo collects everything about the repository's shape.
func (r *Repo) RepositoryInfo(ctx context.Context, defaultBranch string) RepositoryInfo {
	info := RepositoryInfo{
		RootCommits:   r.RootCommits(ctx),
		Shallow:       r.IsShallow(ctx),
		ReplacedRefs:  r.ReplacedRefs(ctx),
		DefaultBranch: defaultBranch,
	}
	info.Remote = r.RemoteURL(ctx)

	if defaultBranch != "" {
		if sha, err := r.ResolveCommit(ctx, "refs/heads/"+defaultBranch); err == nil {
			info.Tip = sha
			if date, err := r.commitDate(ctx, sha); err == nil {
				info.TipDate = date
			}
		} else if sha, err := r.ResolveCommit(ctx, defaultBranch); err == nil {
			info.Tip = sha
		}
	} else {
		if sha, date, err := r.Head(ctx); err == nil {
			info.Tip = sha
			info.TipDate = date
		}
	}
	info.HistoryComplete = !info.Shallow && len(info.ReplacedRefs) == 0 && info.Tip != ""
	return info
}

// historyReasons explains every condition that bounds a conclusion.
func historyReasons(info RepositoryInfo) []string {
	var reasons []string
	if info.Shallow {
		reasons = append(reasons, "repository is a shallow clone; earlier history is unavailable")
	}
	if len(info.ReplacedRefs) > 0 {
		reasons = append(reasons, "refs/replace is configured; object contents are rewritten: "+strings.Join(info.ReplacedRefs, ", "))
	}
	if info.Tip == "" {
		reasons = append(reasons, "default branch tip could not be resolved")
	}
	return reasons
}
