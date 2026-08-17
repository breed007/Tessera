// Package fingerbank is the device-classification enrichment layer (§7). It is
// the inference layer's external brain: it turns a device's DHCP fingerprint
// (plus optional vendor/hostname/user-agent) into a device classification.
//
// Fingerbank is PRIVACY-RELEVANT and disabled by default — querying the API
// transmits your devices' DHCP fingerprints to a third party (Akamai), and
// unknown combinations are auto-added to their database. The Enricher interface
// abstracts the api mode (rate-governed, cached) from the fully-offline local_db
// mode so the rest of the system is identical either way.
package fingerbank

import (
	"context"
	"sort"
	"strings"

	"github.com/breed007/Tessera/internal/observation"
)

// Signature is the set of signals interrogated for a classification. Its cache
// key is the COMBINATION of signals (fingerprint + vendor + user-agents) — NOT
// the MAC: thousands of devices share one fingerprint, so identical signatures
// must collapse to a single lifetime lookup (§7).
type Signature struct {
	DHCPFingerprint string
	DHCPVendor      string
	Hostname        string
	UserAgents      []string
	MAC             string // sent in the request, but NOT part of the cache key
}

// CacheKey is the combination key — deliberately excludes MAC and hostname so
// that the same fingerprint/vendor/UA collapses across all devices and all
// hostnames. (Hostname is per-device and would defeat coalescing.)
func (s Signature) CacheKey() string {
	uas := append([]string(nil), s.UserAgents...)
	sort.Strings(uas)
	return strings.Join([]string{s.DHCPFingerprint, s.DHCPVendor, strings.Join(uas, ",")}, "\x1f")
}

// Verdict is the classification result.
type Verdict struct {
	Found       bool
	DeviceClass string // device path, e.g. "Apple/iPhone"
	OSGuess     string // optional OS, when the path identifies one
	Score       int    // 0–100 → confidence
}

// Enricher classifies a Signature. Implementations: api (rate-governed + cached),
// local_db (offline SQLite), and off (no-op).
type Enricher interface {
	Classify(ctx context.Context, sig Signature) (Verdict, error)
	Mode() string
	Close() error
}

// Reader is the narrow read access the enrichment collector needs over the
// observation log: it scans existing signals (DHCP fingerprints etc.) to know
// what to classify, then writes verdicts back as new observations. This is the
// one collector that reads the log — enrichment is, by nature, over existing
// data — but it still never touches the entity tables.
type Reader interface {
	Each(ctx context.Context, afterID int64, fn func(observation.Observation) error) error
}

// offEnricher is the no-op used when Fingerbank is disabled or mode=off.
type offEnricher struct{}

func (offEnricher) Classify(context.Context, Signature) (Verdict, error) {
	return Verdict{Found: false}, nil
}
func (offEnricher) Mode() string { return "off" }
func (offEnricher) Close() error { return nil }

// NewOff returns the no-op enricher.
func NewOff() Enricher { return offEnricher{} }
