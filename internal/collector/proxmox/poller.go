package proxmox

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/tessera/tessera/internal/collector"
	"github.com/tessera/tessera/internal/observation"
)

// Poller is the long-running Proxmox collector. Each cycle it enumerates nodes,
// their VMs and CTs, reads each guest's config, and emits MAC-keyed observations.
type Poller struct {
	client   *Client
	name     string
	interval time.Duration
	log      *slog.Logger
	*collector.Health
}

// NewPoller builds a Proxmox poller. name distinguishes multiple instances in the
// collector list and health/status display (e.g. "proxmox" or "proxmox:pve-lab").
func NewPoller(name string, cfg Config, interval time.Duration, log *slog.Logger) *Poller {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	if name == "" {
		name = "proxmox"
	}
	if log == nil {
		log = slog.Default()
	}
	return &Poller{client: New(cfg), name: name, interval: interval, log: log, Health: collector.NewHealth(name, "not polled yet")}
}

func (p *Poller) Name() string { return p.name }

// Run polls until ctx is cancelled; a failed cycle is logged and retried.
func (p *Poller) Run(ctx context.Context, sink *observation.Sink) error {
	if err := p.pollOnce(ctx, sink); err != nil && ctx.Err() == nil {
		p.log.Warn("proxmox initial poll failed", "err", err)
	}
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := p.pollOnce(ctx, sink); err != nil && ctx.Err() == nil {
				p.log.Warn("proxmox poll failed", "err", err)
			}
		}
	}
}

func (p *Poller) pollOnce(ctx context.Context, sink *observation.Sink) error {
	now := time.Now()
	nodes, err := p.client.fetchNodes(ctx)
	if err != nil {
		p.Failure(err)
		return err
	}
	var emits []emit
	var firstErr error
	for _, n := range nodes {
		for _, kind := range []string{"qemu", "lxc"} {
			guests, err := p.client.fetchGuests(ctx, n.Node, kind)
			if err != nil {
				firstErr = errOnce(firstErr, err)
				continue
			}
			for _, g := range guests {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				cfg, err := p.client.fetchConfig(ctx, n.Node, kind, g.VMID)
				if err != nil {
					firstErr = errOnce(firstErr, err)
					continue
				}
				emits = append(emits, mapGuest(kind, g.Name, cfg)...)
			}
		}
	}

	written := 0
	for _, e := range emits {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if _, err := sink.Record(ctx, observation.SourceProxmox, e.subjectType, e.subject, e.attr, e.value, e.confidence, observation.At(now)); err != nil {
			p.log.Debug("proxmox observation rejected", "attr", e.attr, "err", err)
			continue
		}
		written++
	}
	p.log.Info("proxmox poll complete", "nodes", len(nodes), "observations", written)
	if firstErr != nil {
		p.Failure(firstErr)
	} else {
		p.Success(fmt.Sprintf("polled — %d guest observations", written))
	}
	return firstErr
}

// Test verifies the connection by listing nodes; returns the node count.
func Test(ctx context.Context, cfg Config) (int, error) {
	nodes, err := New(cfg).fetchNodes(ctx)
	return len(nodes), err
}

func errOnce(existing, err error) error {
	if existing != nil {
		return existing
	}
	return err
}
