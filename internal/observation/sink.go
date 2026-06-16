package observation

import (
	"context"
	"time"

	"github.com/tessera/tessera/internal/netid"
)

// Appender is the narrow write capability the log sink needs. The store
// implements it. Collectors never see anything wider than this — they cannot
// reach the entity tables, which keeps the §2 "one rule" a compile-time fact.
type Appender interface {
	Append(ctx context.Context, obs Observation) (id int64, err error)
}

// Sink is the standard observation-write API that every collector uses (M1
// deliverable). It stamps the collector's identity, defaults the timestamp,
// normalizes the subject identifier, validates, and appends. A collector holds
// a Sink and calls Record; it does not construct Observations by hand.
type Sink struct {
	collectorID string
	appender    Appender
	now         func() time.Time // injectable for tests
}

// NewSink returns a Sink bound to a collector instance id and an Appender.
func NewSink(collectorID string, appender Appender) *Sink {
	return &Sink{collectorID: collectorID, appender: appender, now: time.Now}
}

// Opt customizes a single Record call.
type Opt func(*Observation)

// At sets the time the signal was observed (defaults to now when omitted).
func At(t time.Time) Opt { return func(o *Observation) { o.ObservedAt = t } }

// WithRaw attaches the original payload for audit/debug.
func WithRaw(raw []byte) Opt { return func(o *Observation) { o.Raw = raw } }

// Record builds, normalizes, validates, and appends one observation. The
// subject is normalized according to subjectType (MAC/IP canonical forms) so
// the same device keys identically across collectors, regardless of source.
func (s *Sink) Record(
	ctx context.Context,
	src Source,
	subjectType SubjectType,
	subject string,
	attr Attribute,
	value string,
	confidence int,
	opts ...Opt,
) (int64, error) {
	obs := Observation{
		Source:      src,
		CollectorID: s.collectorID,
		SubjectType: subjectType,
		Subject:     subject,
		Attribute:   attr,
		Value:       value,
		Confidence:  confidence,
		ObservedAt:  s.now(),
	}
	for _, opt := range opts {
		opt(&obs)
	}
	if err := s.normalizeSubject(&obs); err != nil {
		return 0, err
	}
	if err := obs.Validate(); err != nil {
		return 0, err
	}
	return s.appender.Append(ctx, obs)
}

// normalizeSubject canonicalizes MAC/IP subjects so identity keys are stable.
func (s *Sink) normalizeSubject(obs *Observation) error {
	switch obs.SubjectType {
	case SubjectMAC:
		norm, err := netid.NormalizeMAC(obs.Subject)
		if err != nil {
			return err
		}
		obs.Subject = norm
	case SubjectIPv4, SubjectIPv6:
		norm, _, err := netid.NormalizeIP(obs.Subject)
		if err != nil {
			return err
		}
		obs.Subject = norm
	}
	return nil
}
