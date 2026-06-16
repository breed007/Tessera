package passive

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/tessera/tessera/internal/observation"
)

// Sensor is the passive capture collector (§4.1). It runs one capture goroutine
// per configured source, dedups duplicated SPAN frames, parses the discovery
// protocols, and emits observations through the standard Sink. It implements
// collector.Collector.
type Sensor struct {
	sources      []CaptureConfig
	dedupeWindow time.Duration
	protocols    Protocols
	log          *slog.Logger
}

// NewSensor builds a passive sensor over the given capture sources, decoding
// only the enabled discovery protocols.
func NewSensor(sources []CaptureConfig, dedupeWindow time.Duration, protocols Protocols, log *slog.Logger) *Sensor {
	if log == nil {
		log = slog.Default()
	}
	return &Sensor{sources: sources, dedupeWindow: dedupeWindow, protocols: protocols, log: log}
}

// Name identifies the collector (basis of its collector_id).
func (s *Sensor) Name() string { return "passive" }

// Run opens each capture source and reads until ctx is cancelled. A source that
// fails to open (e.g. a no-pcap build, or a missing NIC) is logged and skipped —
// it never stops the others or the daemon. If no source opens, Run idles until
// cancellation so the collector still behaves like a well-mannered goroutine.
func (s *Sensor) Run(ctx context.Context, sink *observation.Sink) error {
	if len(s.sources) == 0 {
		return nil
	}

	var wg sync.WaitGroup
	started := 0
	for _, src := range s.sources {
		h, err := openCapture(src)
		if err != nil {
			if errors.Is(err, ErrNoPcap) {
				s.log.Warn("passive capture unavailable (built without pcap)", "nic", src.NIC)
			} else {
				s.log.Error("passive capture open failed", "nic", src.NIC, "err", err)
			}
			continue
		}
		started++
		s.log.Info("passive capture started", "nic", src.NIC, "kind", src.Kind)
		wg.Add(1)
		go func(src CaptureConfig, h captureHandle) {
			defer wg.Done()
			s.captureLoop(ctx, src, h, sink)
		}(src, h)
	}

	<-ctx.Done()
	wg.Wait()
	if started == 0 {
		s.log.Warn("passive sensor ran with no active capture sources")
	}
	return nil
}

// captureLoop reads, dedups, parses, and emits for one source until ctx is
// cancelled. It recovers any panic at this goroutine edge (§10) and closes the
// handle on cancellation to unblock the blocking read.
func (s *Sensor) captureLoop(ctx context.Context, src CaptureConfig, h captureHandle, sink *observation.Sink) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("passive capture loop panicked (recovered)", "nic", src.NIC, "panic", r)
		}
	}()
	defer h.Close()

	// Closing the handle on cancellation unblocks the blocking next() read.
	go func() {
		<-ctx.Done()
		h.Close()
	}()

	dd := newDeduper(s.dedupeWindow)
	for {
		pkt, err := h.next()
		if err != nil {
			// Closed (cancellation) or a read error: stop this source. SPAN drops
			// are silent at the kernel — absence is never treated as a fact.
			return
		}
		if len(pkt.data) == 0 || dd.duplicate(pkt.data, pkt.ts) {
			continue
		}
		ts := pkt.ts
		if ts.IsZero() {
			ts = time.Now()
		}
		for _, e := range parsePacket(pkt.data, ts, s.protocols) {
			if _, err := sink.Record(ctx, e.source, e.subjectType, e.subject, e.attr, e.value, e.confidence, observation.At(ts)); err != nil {
				s.log.Debug("passive observation rejected", "attr", e.attr, "err", err)
			}
		}
	}
}
