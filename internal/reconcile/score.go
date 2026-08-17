package reconcile

import (
	"math"
	"time"

	"github.com/breed007/Tessera/internal/observation"
)

// scored is an observation paired with its effective (decayed) confidence and
// source tier — the inputs to the §3.3 tiebreak.
type scored struct {
	obs  observation.Observation
	eff  float64 // confidence decayed by age
	tier Tier
}

// conflictFloor is the minimum effective confidence a disagreeing observation
// must carry before it is worth recording as a conflict — keeps heavily-decayed
// or low-confidence noise from opening spurious conflicts. (Configurable later.)
const conflictFloor = 10.0

// effective applies recency decay to a raw confidence (§3.3): confidence halves
// every confidenceHalfLife of age. now is captured once per rebuild so a single
// reconciliation is internally consistent.
func effective(rawConfidence int, observedAt, now time.Time, halfLife time.Duration) float64 {
	age := now.Sub(observedAt)
	if age <= 0 {
		return float64(rawConfidence)
	}
	if halfLife <= 0 {
		return float64(rawConfidence)
	}
	return float64(rawConfidence) * math.Pow(0.5, age.Seconds()/halfLife.Seconds())
}

// better reports whether a should beat b for "current value" of an attribute:
// higher effective confidence, then lower (better) source tier, then more recent
// observation, then higher id — the last two purely for deterministic replay.
func better(a, b scored) bool {
	if a.eff != b.eff {
		return a.eff > b.eff
	}
	if a.tier != b.tier {
		return a.tier < b.tier
	}
	if !a.obs.ObservedAt.Equal(b.obs.ObservedAt) {
		return a.obs.ObservedAt.After(b.obs.ObservedAt)
	}
	return a.obs.ID > b.obs.ID
}

// resolver accumulates the candidate observations for one (subject, attribute)
// and resolves the current value under the §3.3 rules.
type resolver struct {
	cands []scored
}

func (r *resolver) add(s scored) { r.cands = append(r.cands, s) }

// winner returns the current value's observation. Manual annotations are
// authoritative and always win (§3.2) — the latest manual beats any discovered
// value. Otherwise the highest effective-confidence candidate wins.
func (r *resolver) winner() (scored, bool) {
	var best, manual scored
	var haveBest, haveManual bool
	for _, c := range r.cands {
		if c.obs.Source == observation.SourceManual {
			if !haveManual || laterManual(c, manual) {
				manual, haveManual = c, true
			}
			continue
		}
		if !haveBest || better(c, best) {
			best, haveBest = c, true
		}
	}
	if haveManual {
		return manual, true
	}
	return best, haveBest
}

// winnerByConfidence resolves purely on effective confidence + source tier + age,
// with NO manual-wins short-circuit. Used for IP ownership: a hand-documented
// binding (e.g. a manually-added device) must not steal a live, higher-confidence
// binding off the real host — discovery wins, and the manual binding only takes
// the address when it's genuinely uncontested.
func (r *resolver) winnerByConfidence() (scored, bool) {
	var best scored
	var have bool
	for _, c := range r.cands {
		if !have || better(c, best) {
			best, have = c, true
		}
	}
	return best, have
}

// laterManual breaks ties between manual annotations by recency then id.
func laterManual(a, b scored) bool {
	if !a.obs.ObservedAt.Equal(b.obs.ObservedAt) {
		return a.obs.ObservedAt.After(b.obs.ObservedAt)
	}
	return a.obs.ID > b.obs.ID
}

// conflict finds the strongest candidate that disagrees with the winner on both
// value and source — the §3.3 "two sources disagree" case. It is only meaningful
// for high-value attributes (the caller decides which). The winner stays current;
// bestFromSource returns the strongest candidate from a given source, or
// ok=false if that source contributed nothing. Used by the source-precedence
// policy ("always prefer source X for attribute Y").
func (r *resolver) bestFromSource(src string) (scored, bool) {
	var best scored
	var have bool
	for _, c := range r.cands {
		if string(c.obs.Source) == src {
			if !have || better(c, best) {
				best, have = c, true
			}
		}
	}
	return best, have
}

// support returns how many candidate observations carry a given value and the
// most recent time it was observed — the provenance shown for a conflict side.
func (r *resolver) support(value string) (count int, last time.Time) {
	for _, c := range r.cands {
		if c.obs.Value == value {
			count++
			if c.obs.ObservedAt.After(last) {
				last = c.obs.ObservedAt
			}
		}
	}
	return count, last
}

// the disagreement is surfaced.
func (r *resolver) conflict(winner scored) (scored, bool) {
	var alt scored
	var have bool
	for _, c := range r.cands {
		if c.obs.Value == winner.obs.Value || c.obs.Source == winner.obs.Source {
			continue
		}
		if c.eff < conflictFloor {
			continue
		}
		if !have || better(c, alt) {
			alt, have = c, true
		}
	}
	return alt, have
}
