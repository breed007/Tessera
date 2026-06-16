package observation

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

// BatchAppender is an optional fast path: an Appender that can persist many
// observations in one transaction. The store implements it; BufferedAppender
// uses it to amortize write cost under a busy SPAN.
type BatchAppender interface {
	AppendBatch(ctx context.Context, obs []Observation) error
}

// BufferedAppender decouples high-rate collectors (the passive sensor) from
// database write latency (§M8 backpressure). Append never blocks the caller: it
// enqueues into a bounded channel and a background worker flushes batches. When
// the queue is full it DROPS and counts — under SPAN overload, dropping is the
// correct behavior (§4.1: SPAN is best-effort; absence is never a fact), far
// better than stalling packet capture.
type BufferedAppender struct {
	out        Appender
	batch      BatchAppender // non-nil if out supports batch writes
	ch         chan Observation
	log        *slog.Logger
	dropped    atomic.Int64
	lastReport int64

	batchSize  int
	flushEvery time.Duration
}

// NewBufferedAppender wraps out with a queue of bufSize. A non-positive bufSize
// defaults to a sensible buffer.
func NewBufferedAppender(out Appender, bufSize int, log *slog.Logger) *BufferedAppender {
	if bufSize <= 0 {
		bufSize = 8192
	}
	if log == nil {
		log = slog.Default()
	}
	b := &BufferedAppender{
		out:        out,
		ch:         make(chan Observation, bufSize),
		log:        log,
		batchSize:  256,
		flushEvery: 500 * time.Millisecond,
	}
	if ba, ok := out.(BatchAppender); ok {
		b.batch = ba
	}
	return b
}

// Append enqueues an observation without blocking. The returned id is always 0
// (it isn't known until the async flush); collectors ignore it.
func (b *BufferedAppender) Append(_ context.Context, obs Observation) (int64, error) {
	select {
	case b.ch <- obs:
	default:
		b.dropped.Add(1) // queue full → drop (SPAN overload); counted and reported
	}
	return 0, nil
}

// Dropped returns the total number of observations dropped due to backpressure.
func (b *BufferedAppender) Dropped() int64 { return b.dropped.Load() }

// Run flushes batches until ctx is cancelled, then drains and flushes whatever
// remains so a clean shutdown doesn't lose buffered observations.
func (b *BufferedAppender) Run(ctx context.Context) {
	buf := make([]Observation, 0, b.batchSize)
	ticker := time.NewTicker(b.flushEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			b.drain(&buf)
			b.flush(buf)
			return
		case obs := <-b.ch:
			buf = append(buf, obs)
			if len(buf) >= b.batchSize {
				b.flush(buf)
				buf = buf[:0]
			}
		case <-ticker.C:
			if len(buf) > 0 {
				b.flush(buf)
				buf = buf[:0]
			}
			b.reportDrops()
		}
	}
}

// drain pulls any queued observations into buf without blocking (shutdown path).
func (b *BufferedAppender) drain(buf *[]Observation) {
	for {
		select {
		case obs := <-b.ch:
			*buf = append(*buf, obs)
		default:
			return
		}
	}
}

func (b *BufferedAppender) flush(buf []Observation) {
	if len(buf) == 0 {
		return
	}
	ctx := context.Background()
	if b.batch != nil {
		if err := b.batch.AppendBatch(ctx, buf); err != nil {
			b.log.Error("buffered append: batch flush failed", "n", len(buf), "err", err)
		}
		return
	}
	for _, obs := range buf {
		if _, err := b.out.Append(ctx, obs); err != nil {
			b.log.Debug("buffered append: row failed", "err", err)
		}
	}
}

func (b *BufferedAppender) reportDrops() {
	if d := b.dropped.Load(); d > b.lastReport {
		b.log.Warn("observation backpressure: dropping under load (SPAN is best-effort)", "dropped_total", d)
		b.lastReport = d
	}
}
