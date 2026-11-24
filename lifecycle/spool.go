package lifecycle

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// Spool stores occurrence records in a private temporary directory.
//
// Records are buffered in memory up to chunkSize, sorted, and flushed as a
// sorted run file. Final grouping is a k-way merge over the runs, so peak
// memory is bounded by chunkSize regardless of history size.
type Spool struct {
	dir      string
	chunk    []Occurrence
	chunkCap int
	runs     []string

	total int
}

func NewSpool(dir string, chunkCap int) (*Spool, error) {
	if chunkCap <= 0 {
		chunkCap = DefaultChunkSize
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create spool directory: %w", err)
	}
	return &Spool{
		dir:      dir,
		chunk:    make([]Occurrence, 0, chunkCap),
		chunkCap: chunkCap,
	}, nil
}

func (s *Spool) Add(o Occurrence) error {
	// Exact duplicates are removed during the merge (records are sorted and
	// adjacent), so detection here needs no unbounded set.
	s.chunk = append(s.chunk, o)
	s.total++
	if len(s.chunk) >= s.chunkCap {
		return s.flush()
	}
	return nil
}

func (s *Spool) flush() error {
	if len(s.chunk) == 0 {
		return nil
	}
	// Stable sorting keeps output deterministic for records that compare
	// equal.
	sort.SliceStable(s.chunk, func(i, j int) bool { return lessOccurrence(s.chunk[i], s.chunk[j]) })

	path := filepath.Join(s.dir, fmt.Sprintf("run-%06d.spool", len(s.runs)))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create spool run: %w", err)
	}
	w := bufio.NewWriterSize(f, 1<<20)
	for i := range s.chunk {
		if err := writeOccurrence(w, &s.chunk[i]); err != nil {
			_ = f.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	s.runs = append(s.runs, path)
	s.chunk = s.chunk[:0]
	return nil
}

// Group merges all runs and invokes fn once per (SecretID, RuleID) in
// deterministic order. Occurrences arrive sorted by commit date/commit.
//
// Runs are merged in bounded batches, so the number of open files stays
// bounded no matter how much history was scanned.
func (s *Spool) Group(fn func(group []Occurrence) error) error {
	if err := s.flush(); err != nil {
		return err
	}
	if len(s.runs) == 0 {
		return nil
	}
	if err := s.compactRuns(); err != nil {
		return err
	}

	readers := make([]*runReader, 0, len(s.runs))
	defer func() {
		for _, r := range readers {
			_ = r.Close()
		}
	}()

	heap := &occHeap{}
	for _, path := range s.runs {
		r, err := openRun(path)
		if err != nil {
			return err
		}
		readers = append(readers, r)
		o, ok, err := r.next()
		if err != nil {
			return err
		}
		if ok {
			heap.push(&heapItem{occ: o, reader: r})
		}
	}

	var (
		group   []Occurrence
		curID   string
		curRule string
		haveCur bool
	)
	for heap.Len() > 0 {
		item := heap.pop()
		o := item.occ

		if !haveCur {
			curID, curRule, haveCur = o.SecretID, o.RuleID, true
		} else if o.SecretID != curID || o.RuleID != curRule {
			if err := fn(dedupeGroup(group)); err != nil {
				return err
			}
			group = group[:0]
			curID, curRule = o.SecretID, o.RuleID
		}
		group = append(group, o)

		next, ok, err := item.reader.next()
		if err != nil {
			return err
		}
		if ok {
			item.occ = next
			heap.push(item)
		}
	}

	if len(group) > 0 {
		if err := fn(dedupeGroup(group)); err != nil {
			return err
		}
	}
	return nil
}

// dedupeGroup removes byte-identical locations that appear more than once,
// keeping the first in sorted order. Identical (secret, rule, commit, file,
// position) records are the only ones collapsed; different positions in the
// same commit are all retained.
func dedupeGroup(group []Occurrence) []Occurrence {
	out := group[:0]
	for i := range group {
		if i > 0 && sameLocation(&group[i-1], &group[i]) {
			continue
		}
		out = append(out, group[i])
	}
	return out
}

func sameLocation(a, b *Occurrence) bool {
	return a.SecretID == b.SecretID &&
		a.RuleID == b.RuleID &&
		a.Commit == b.Commit &&
		a.File == b.File &&
		a.StartLine == b.StartLine &&
		a.EndLine == b.EndLine &&
		a.StartColumn == b.StartColumn &&
		a.EndColumn == b.EndColumn
}

func lessLocation(a, b *Occurrence) bool {
	if a.Commit != b.Commit {
		return a.Commit < b.Commit
	}
	if a.File != b.File {
		return a.File < b.File
	}
	if a.StartLine != b.StartLine {
		return a.StartLine < b.StartLine
	}
	if a.EndLine != b.EndLine {
		return a.EndLine < b.EndLine
	}
	if a.StartColumn != b.StartColumn {
		return a.StartColumn < b.StartColumn
	}
	return a.EndColumn < b.EndColumn
}

// Close removes the spool directory and releases buffered records.
func (s *Spool) Close() error {
	s.chunk = nil
	return os.RemoveAll(s.dir)
}

func lessOccurrence(a, b Occurrence) bool {
	if a.SecretID != b.SecretID {
		return a.SecretID < b.SecretID
	}
	if a.RuleID != b.RuleID {
		return a.RuleID < b.RuleID
	}
	if a.Date != b.Date {
		return a.Date < b.Date
	}
	if a.Commit != b.Commit {
		return a.Commit < b.Commit
	}
	return lessLocation(&a, &b)
}

func writeOccurrence(w io.Writer, o *Occurrence) error {
	if err := writeString(w, o.SecretID); err != nil {
		return err
	}
	if err := writeString(w, o.RuleID); err != nil {
		return err
	}
	if err := writeString(w, o.Commit); err != nil {
		return err
	}
	if err := writeString(w, o.Date); err != nil {
		return err
	}
	if err := writeString(w, o.File); err != nil {
		return err
	}
	var buf [16]byte
	binary.LittleEndian.PutUint32(buf[0:], uint32(o.StartLine))
	binary.LittleEndian.PutUint32(buf[4:], uint32(o.EndLine))
	binary.LittleEndian.PutUint32(buf[8:], uint32(o.StartColumn))
	binary.LittleEndian.PutUint32(buf[12:], uint32(o.EndColumn))
	_, err := w.Write(buf[:])
	return err
}

func writeString(w io.Writer, s string) error {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], uint32(len(s)))
	if _, err := w.Write(buf[:]); err != nil {
		return err
	}
	_, err := io.WriteString(w, s)
	return err
}

type runReader struct {
	f *os.File
	r *bufio.Reader
}

func openRun(path string) (*runReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open spool run: %w", err)
	}
	return &runReader{f: f, r: bufio.NewReaderSize(f, 1<<20)}, nil
}

func (r *runReader) Close() error { return r.f.Close() }

// next returns the next occurrence, or ok=false at end of run.
func (r *runReader) next() (Occurrence, bool, error) {
	var o Occurrence
	var err error
	if o.SecretID, err = readString(r.r); err != nil {
		if err == io.EOF {
			return o, false, nil
		}
		return o, false, err
	}
	if o.RuleID, err = readString(r.r); err != nil {
		return o, false, err
	}
	if o.Commit, err = readString(r.r); err != nil {
		return o, false, err
	}
	if o.Date, err = readString(r.r); err != nil {
		return o, false, err
	}
	if o.File, err = readString(r.r); err != nil {
		return o, false, err
	}
	var buf [16]byte
	if _, err := io.ReadFull(r.r, buf[:]); err != nil {
		return o, false, err
	}
	o.StartLine = int(int32(binary.LittleEndian.Uint32(buf[0:])))
	o.EndLine = int(int32(binary.LittleEndian.Uint32(buf[4:])))
	o.StartColumn = int(int32(binary.LittleEndian.Uint32(buf[8:])))
	o.EndColumn = int(int32(binary.LittleEndian.Uint32(buf[12:])))
	return o, true, nil
}

func readString(r *bufio.Reader) (string, error) {
	var buf [4]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return "", err
	}
	n := binary.LittleEndian.Uint32(buf[:])
	if n == 0 {
		return "", nil
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return string(b), nil
}

type heapItem struct {
	occ    Occurrence
	reader *runReader
}

type occHeap []*heapItem

func (h occHeap) Len() int           { return len(h) }
func (h occHeap) Less(i, j int) bool { return lessOccurrence(h[i].occ, h[j].occ) }
func (h occHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *occHeap) push(x *heapItem)  { *h = append(*h, x); siftUp(*h, len(*h)-1) }
func (h *occHeap) pop() *heapItem {
	old := *h
	n := len(old)
	item := old[0]
	old[0] = old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	if len(*h) > 0 {
		siftDown(*h, 0)
	}
	return item
}

func siftUp(h occHeap, i int) {
	for i > 0 {
		p := (i - 1) / 2
		if !h.Less(i, p) {
			break
		}
		h.Swap(i, p)
		i = p
	}
}

func siftDown(h occHeap, i int) {
	n := len(h)
	for {
		l, r := 2*i+1, 2*i+2
		smallest := i
		if l < n && h.Less(l, smallest) {
			smallest = l
		}
		if r < n && h.Less(r, smallest) {
			smallest = r
		}
		if smallest == i {
			return
		}
		h.Swap(i, smallest)
		i = smallest
	}
}

// compactRuns merges the sorted runs in batches of minFanIn until at most
// minFanIn remain, keeping the merge fan-in and open-file count bounded.
func (s *Spool) compactRuns() error {
	for len(s.runs) > minFanIn {
		batch := minFanIn
		merged, err := s.mergeRuns(s.runs[:batch])
		if err != nil {
			return err
		}
		rest := append([]string(nil), s.runs[batch:]...)
		for _, path := range s.runs[:batch] {
			_ = os.Remove(path)
		}
		s.runs = append([]string{merged}, rest...)
	}
	return nil
}

// mergeRuns merges one batch of runs into a single new run and returns its
// path. Identical adjacent records are not collapsed here; Group does that so
// grouping and merging stay in one place.
func (s *Spool) mergeRuns(paths []string) (string, error) {
	readers := make([]*runReader, 0, len(paths))
	defer func() {
		for _, r := range readers {
			_ = r.Close()
		}
	}()

	heap := &occHeap{}
	for _, path := range paths {
		r, err := openRun(path)
		if err != nil {
			return "", err
		}
		readers = append(readers, r)
		o, ok, err := r.next()
		if err != nil {
			return "", err
		}
		if ok {
			heap.push(&heapItem{occ: o, reader: r})
		}
	}

	path := filepath.Join(s.dir, fmt.Sprintf("merge-%06d.spool", len(s.runs)))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("create merged run: %w", err)
	}
	w := bufio.NewWriterSize(f, 1<<20)
	for heap.Len() > 0 {
		item := heap.pop()
		if err := writeOccurrence(w, &item.occ); err != nil {
			_ = f.Close()
			return "", err
		}
		next, ok, err := item.reader.next()
		if err != nil {
			_ = f.Close()
			return "", err
		}
		if ok {
			item.occ = next
			heap.push(item)
		}
	}
	if err := w.Flush(); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return path, nil
}
