package fingerbank

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/breed007/Tessera/internal/collector"
	"github.com/breed007/Tessera/internal/observation"
)

// Collector is the enrichment collector. Each cycle it scans the observation log
// for per-MAC signals (the DHCP fingerprint is the primary input), coalesces
// MACs that share a signature, asks the Enricher to classify each unique
// signature, and writes device_class observations back into the log. It is the
// one collector that reads the log — enrichment is over existing data — but it
// still never touches the entity tables.
type Collector struct {
	enricher Enricher
	reader   Reader
	interval time.Duration
	log      *slog.Logger
	*collector.Health

	// lastSig remembers the signature last emitted per MAC so an unchanged
	// signature isn't re-emitted every cycle (which would bloat the log).
	lastSig map[string]string
}

// NewCollector builds the enrichment collector.
func NewCollector(enricher Enricher, reader Reader, interval time.Duration, log *slog.Logger) *Collector {
	if interval <= 0 {
		interval = time.Minute
	}
	if log == nil {
		log = slog.Default()
	}
	return &Collector{
		enricher: enricher, reader: reader, interval: interval, log: log,
		Health:  collector.NewHealth("fingerbank", "mode="+enricher.Mode()),
		lastSig: map[string]string{},
	}
}

func (c *Collector) Name() string { return "fingerbank" }

// Run enriches immediately, then once per interval, until ctx is cancelled.
func (c *Collector) Run(ctx context.Context, sink *observation.Sink) error {
	c.runOnce(ctx, sink)
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return c.enricher.Close()
		case <-ticker.C:
			c.runOnce(ctx, sink)
		}
	}
}

type macSignals struct {
	fingerprint string
	vendor      string
	hostname    string
	userAgents  []string
}

// runOnce scans signals, coalesces by signature, classifies, and emits.
func (c *Collector) runOnce(ctx context.Context, sink *observation.Sink) {
	signals := c.collectSignals(ctx)
	if len(signals) == 0 {
		return
	}

	// Group MACs by signature so one Classify call covers every device that
	// shares the combination (§7 coalesce).
	bySig := map[string]Signature{}
	macsBySig := map[string][]string{}
	for mac, s := range signals {
		if s.fingerprint == "" {
			continue // the DHCP fingerprint is the primary, required input
		}
		sig := Signature{
			DHCPFingerprint: s.fingerprint,
			DHCPVendor:      s.vendor,
			Hostname:        s.hostname,
			UserAgents:      s.userAgents,
			MAC:             mac,
		}
		key := sig.CacheKey()
		if c.lastSig[mac] == key {
			continue // already classified & emitted for this signature
		}
		bySig[key] = sig
		macsBySig[key] = append(macsBySig[key], mac)
	}

	emitted := 0
	attempted := len(bySig)
	var lastErr error
	for key, sig := range bySig {
		v, err := c.enricher.Classify(ctx, sig)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// 429/backoff or transient — leave lastSig unset so we retry later.
			lastErr = err
			c.log.Debug("fingerbank classify deferred", "err", err)
			continue
		}
		for _, mac := range macsBySig[key] {
			c.lastSig[mac] = key // mark done (even on not-found, to avoid re-query churn)
		}
		if !v.Found {
			continue
		}
		for _, mac := range macsBySig[key] {
			if _, err := sink.Record(ctx, observation.SourceFingerbank, observation.SubjectMAC, mac,
				observation.AttrDeviceClass, v.DeviceClass, v.Score); err != nil {
				c.log.Debug("fingerbank observation rejected", "err", err)
				continue
			}
			if v.OSGuess != "" {
				_, _ = sink.Record(ctx, observation.SourceFingerbank, observation.SubjectMAC, mac,
					observation.AttrOSGuess, v.OSGuess, v.Score)
			}
			emitted++
		}
	}
	if attempted > 0 {
		if lastErr != nil {
			c.Failure(lastErr)
		} else {
			c.Success(fmt.Sprintf("mode=%s — classified %d", c.enricher.Mode(), emitted))
		}
	}
	if emitted > 0 {
		c.log.Info("fingerbank enrichment complete", "classified", emitted, "mode", c.enricher.Mode())
	}
}

// collectSignals folds the log into the latest signal set per MAC. Each is
// ordered by (observed_at, id), so the last value for each attribute wins.
func (c *Collector) collectSignals(ctx context.Context) map[string]*macSignals {
	signals := map[string]*macSignals{}
	get := func(mac string) *macSignals {
		s := signals[mac]
		if s == nil {
			s = &macSignals{}
			signals[mac] = s
		}
		return s
	}
	_ = c.reader.Each(ctx, 0, func(obs observation.Observation) error {
		if obs.SubjectType != observation.SubjectMAC {
			return nil
		}
		switch obs.Attribute {
		case observation.AttrDHCPFingerprint:
			get(obs.Subject).fingerprint = obs.Value
		case observation.AttrDHCPVendor:
			get(obs.Subject).vendor = obs.Value
		case observation.AttrHostname:
			get(obs.Subject).hostname = obs.Value
		case observation.AttrUserAgent:
			s := get(obs.Subject)
			s.userAgents = append(s.userAgents, obs.Value)
		}
		return nil
	})
	return signals
}
