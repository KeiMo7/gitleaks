package sources

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/zricethezav/gitleaks/v8/logging"
)

// BatchBlobReader serves repository blobs through a single long-lived
// `git cat-file --batch` process, avoiding one process fork per changed
// file. It is safe for concurrent use.
type BatchBlobReader struct {
	repoPath string

	mu     sync.Mutex
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
}

// NewBatchBlobReader starts the batch process for the given repository.
func NewBatchBlobReader(ctx context.Context, repoPath string) (*BatchBlobReader, error) {
	cmd := exec.CommandContext(ctx, "git",
		"-C", filepath.Clean(repoPath), "cat-file", "--batch",
	)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	return &BatchBlobReader{
		repoPath: repoPath,
		cmd:      cmd,
		stdin:    stdin,
		stdout:   bufio.NewReaderSize(stdoutPipe, 64*1024),
	}, nil
}

// Blob returns the content of revision:path. A missing object is reported as
// an error so the caller can log and skip the file.
func (b *BatchBlobReader) Blob(revision, path string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.cmd == nil {
		return nil, fmt.Errorf("blob reader is closed")
	}

	if _, err := fmt.Fprintf(b.stdin, "%s:%s\n", revision, path); err != nil {
		return nil, err
	}

	header, err := b.stdout.ReadString('\n')
	if err != nil {
		return nil, err
	}
	header = strings.TrimSpace(header)

	// Error header, e.g. `<input> missing`.
	if strings.HasSuffix(header, " missing") {
		return nil, fmt.Errorf("git cat-file: %s", header)
	}

	fields := strings.Fields(header)
	if len(fields) < 3 {
		return nil, fmt.Errorf("unexpected git cat-file header: %q", header)
	}
	size, err := strconv.Atoi(fields[2])
	if err != nil {
		return nil, fmt.Errorf("unexpected blob size %q: %w", fields[2], err)
	}

	content := make([]byte, size+1) // +1 for the trailing newline git emits
	if _, err := io.ReadFull(b.stdout, content); err != nil {
		return nil, err
	}
	return content[:size], nil
}

// Close terminates the batch process.
func (b *BatchBlobReader) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.cmd == nil {
		return nil
	}
	_ = b.stdin.Close()

	// Drain remaining output so the process can exit cleanly.
	drain := bytes.Buffer{}
	_, _ = io.Copy(&drain, b.stdout)

	err := b.cmd.Wait()
	b.cmd = nil
	if err != nil && !strings.Contains(err.Error(), "broken pipe") {
		logging.Debug().Err(err).Msg("git cat-file --batch exited")
	}
	return nil
}
