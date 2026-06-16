package active

import (
	"context"
	"sync"
	"time"
)

// limiter paces probes to at most ratePerSec across all concurrent workers
// (§4.2: a global probe rate limit, defaulting gentle). It is a simple spacing
// limiter — each grant is at least 1/ratePerSec after the previous — which keeps
// the prober from ever bursting hard against the network. burst tokens allow a
// small initial cushion.
type limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
	now      func() time.Time
	sleep    func(context.Context, time.Duration) error
}

func newLimiter(ratePerSec int) *limiter {
	if ratePerSec <= 0 {
		ratePerSec = 20 // gentle default (§5)
	}
	return &limiter{
		interval: time.Second / time.Duration(ratePerSec),
		now:      time.Now,
		sleep:    sleepCtx,
	}
}

// wait blocks until the next probe is permitted or ctx is cancelled.
func (l *limiter) wait(ctx context.Context) error {
	l.mu.Lock()
	now := l.now()
	if l.next.Before(now) {
		l.next = now
	}
	wait := l.next.Sub(now)
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()

	if wait <= 0 {
		return ctx.Err()
	}
	return l.sleep(ctx, wait)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
