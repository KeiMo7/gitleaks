package sources

import (
	"context"

	"golang.org/x/sync/semaphore"
)

// ByteBudget bounds the total number of bytes that concurrent scans may
// hold in read buffers, carry windows and peek headroom. It is shared by
// every file scanned within a run so that the aggregate memory footprint
// stays under a configurable ceiling no matter how many large files are
// scanned in parallel.
//
// A nil *ByteBudget is valid and imposes no limit, which preserves the
// historical (unbounded) default behavior.
type ByteBudget struct {
	sem *semaphore.Weighted
	max int64
}

// NewByteBudget returns a budget allowing up to maxBytes to be held
// concurrently. A maxBytes <= 0 returns nil, i.e. no limit.
func NewByteBudget(maxBytes int64) *ByteBudget {
	if maxBytes <= 0 {
		return nil
	}
	return &ByteBudget{
		sem: semaphore.NewWeighted(maxBytes),
		max: maxBytes,
	}
}

// Max returns the total budget in bytes, or 0 when unbounded.
func (b *ByteBudget) Max() int64 {
	if b == nil {
		return 0
	}
	return b.max
}

// Acquire blocks until n bytes of budget are available, the context is
// canceled, or the budget is nil. It returns a release function that must
// be called when the memory is no longer needed. Acquiring more than the
// total budget is clamped to the budget itself so a single oversized
// request can still make progress instead of deadlocking.
func (b *ByteBudget) Acquire(ctx context.Context, n int64) (release func()) {
	if b == nil {
		return func() {}
	}
	if n > b.max {
		n = b.max
	}
	if n <= 0 {
		return func() {}
	}
	if err := b.sem.Acquire(ctx, n); err != nil {
		// Context canceled: proceed without budget rather than blocking
		// the scan; cancellation will unwind the scan shortly anyway.
		return func() {}
	}
	return func() { b.sem.Release(n) }
}
