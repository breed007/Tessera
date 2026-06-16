package unifi

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/tessera/tessera/internal/observation"
)

// Poller is the long-running UniFi collector. On each cycle it fetches clients,
// devices, and configured networks, maps them to observations, and writes them
// through the standard Sink. It implements collector.Collector.
type Poller struct {
	client   *Client
	interval time.Duration
	log      *slog.Logger
}

// NewPoller builds a UniFi poller from a connection config and poll interval.
func NewPoller(cfg Config, interval time.Duration, log *slog.Logger) (*Poller, error) {
	cl, err := New(cfg)
	if err != nil {
		return nil, err
	}
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	if log == nil {
		log = slog.Default()
	}
	return &Poller{client: cl, interval: interval, log: log}, nil
}

// Name identifies the collector (basis of its collector_id).
func (p *Poller) Name() string { return "unifi" }

// Run polls the controller every interval until ctx is cancelled. One poll
// failure is logged and retried next cycle — a controller hiccup never stops the
// collector (and never panics across the goroutine boundary; the app's runner
// also recovers).
func (p *Poller) Run(ctx context.Context, sink *observation.Sink) error {
	// Poll once immediately so the inventory populates without waiting a cycle.
	if err := p.pollOnce(ctx, sink); err != nil && ctx.Err() == nil {
		p.log.Warn("unifi initial poll failed", "err", err)
	}

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := p.pollOnce(ctx, sink); err != nil && ctx.Err() == nil {
				p.log.Warn("unifi poll failed", "err", err)
			}
		}
	}
}

// pollOnce performs a single fetch+emit cycle. Partial failures are tolerated:
// if clients fetch fails we still try devices/networks, so one bad endpoint
// doesn't blank the whole contribution.
func (p *Poller) pollOnce(ctx context.Context, sink *observation.Sink) error {
	now := time.Now()
	var emits []emit
	var firstErr error

	if clients, err := p.client.fetchClients(ctx); err != nil {
		firstErr = errOnce(firstErr, err)
	} else {
		emits = append(emits, mapClients(clients)...)
	}
	if devices, err := p.client.fetchDevices(ctx); err != nil {
		firstErr = errOnce(firstErr, err)
	} else {
		emits = append(emits, mapDevices(devices)...)
	}
	if networks, err := p.client.fetchNetworks(ctx); err != nil {
		firstErr = errOnce(firstErr, err)
	} else {
		emits = append(emits, mapNetworks(networks)...)
	}

	written := 0
	for _, e := range emits {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if _, err := sink.Record(ctx, observation.SourceUniFi, e.subjectType, e.subject,
			e.attr, e.value, e.confidence, observation.At(now)); err != nil {
			// A single malformed record (e.g. a MAC the controller reported in an
			// odd form) shouldn't abort the cycle; log at debug and continue.
			p.log.Debug("unifi observation rejected", "attr", e.attr, "err", err)
			continue
		}
		written++
	}
	p.log.Info("unifi poll complete", "observations", written)
	return firstErr
}

func errOnce(existing, err error) error {
	if existing != nil {
		return existing
	}
	return fmt.Errorf("unifi poll: %w", err)
}
