package fingerbank

import (
	"context"
	"sync"
	"time"
)

// governor is the token-bucket rate limiter that guarantees we stay UNDER
// Fingerbank's free-tier ceiling (300/hr → HTTP 429). It refills at
// maxPerHour/3600 tokens per second with a small burst, and supports a backoff
// horizon set on 429/5xx so we never spin-retry a rate-limited endpoint (§7).
type governor struct {
	mu           sync.Mutex
	ratePerSec   float64
	burst        float64
	tokens       float64
	last         time.Time
	backoffUntil time.Time

	now   func() time.Time
	sleep func(context.Context, time.Duration) error
}

func newGovernor(maxPerHour, burst int) *governor {
	if maxPerHour <= 0 {
		maxPerHour = 250 // deliberate margin under the 300/hr ceiling (§5)
	}
	if burst <= 0 {
		burst = 10
	}
	return &governor{
		ratePerSec: float64(maxPerHour) / 3600.0,
		burst:      float64(burst),
		tokens:     float64(burst),
		now:        time.Now,
		sleep:      sleepCtx,
	}
}

// acquire blocks until a token is available (respecting any active backoff) or
// ctx is cancelled.
func (g *governor) acquire(ctx context.Context) error {
	for {
		g.mu.Lock()
		now := g.now()
		if !g.last.IsZero() {
			g.tokens += now.Sub(g.last).Seconds() * g.ratePerSec
			if g.tokens > g.burst {
				g.tokens = g.burst
			}
		}
		g.last = now

		if now.Before(g.backoffUntil) {
			wait := g.backoffUntil.Sub(now)
			g.mu.Unlock()
			if err := g.sleep(ctx, wait); err != nil {
				return err
			}
			continue
		}
		if g.tokens >= 1 {
			g.tokens--
			g.mu.Unlock()
			return nil
		}
		need := (1 - g.tokens) / g.ratePerSec
		g.mu.Unlock()
		if err := g.sleep(ctx, time.Duration(need*float64(time.Second))); err != nil {
			return err
		}
	}
}

// backoff pushes the next-allowed time out by d (set on 429/5xx, with jitter
// applied by the caller). The hour-window is the natural reset horizon.
func (g *governor) backoff(d time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	until := g.now().Add(d)
	if until.After(g.backoffUntil) {
		g.backoffUntil = until
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
