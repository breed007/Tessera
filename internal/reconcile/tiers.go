package reconcile

import "github.com/tessera/tessera/internal/observation"

// Tier is the source-priority tier used as a tiebreak when two observations
// carry equal (decayed) confidence (§3.3). Lower wins.
type Tier int

const (
	TierGround      Tier = 0 // directly observed L2 facts
	TierStrong      Tier = 1 // reliable liveness / first-party data
	TierInferential Tier = 2 // educated classification
)

// tierFor returns the default source-priority tier for an observation (§3.3
// table). UniFi is dual-tier: its port↔MAC/topology facts are ground truth,
// while its device fingerprints are merely strong — so the tier depends on the
// attribute, not just the source. This default mapping is intended to be made
// configurable in a later milestone; the logic that consumes it does not care
// where the number comes from.
func tierFor(obs observation.Observation) Tier {
	switch obs.Source {
	case observation.SourceManual:
		// Manual is authoritative and handled before tiers ever matter; give it
		// ground truth here for completeness.
		return TierGround
	case observation.SourcePassiveARP, observation.SourceActiveARP:
		return TierGround
	case observation.SourceUniFi:
		switch obs.Attribute {
		case observation.AttrSwitchPort, observation.AttrVLANMembership, observation.AttrIPBinding:
			return TierGround // port↔MAC / configured-network facts
		default:
			return TierStrong // UniFi's own client fingerprints
		}
	case observation.SourceActiveICMP, observation.SourceActiveTCP, observation.SourcePassiveDHCP:
		return TierStrong
	case observation.SourceFingerbank,
		observation.SourcePassiveMDNS, observation.SourcePassiveSSDP, observation.SourcePassiveNBNS:
		return TierInferential
	default:
		return TierInferential
	}
}
