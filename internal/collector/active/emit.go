package active

import "github.com/tessera/tessera/internal/observation"

// emit is one observation produced by a probe, carrying its own source
// (active_icmp, active_tcp, active_arp, active_rdns, active_snmp).
type emit struct {
	source      observation.Source
	subjectType observation.SubjectType
	subject     string
	attr        observation.Attribute
	value       string
	confidence  int
}

// Confidence levels for active-probe observations. ARP-cache bindings are
// ground truth; ICMP/TCP liveness is strong; rDNS/SNMP classification is softer.
const (
	confARPBinding = 96
	confICMPLive   = 90
	confTCPOpen    = 85
	confTCPLive    = 80
	confTCPBanner  = 75
	confRDNSHost   = 70
	confSNMPName   = 80
	confSNMPDescr  = 70
	// UDP: a tailored-payload reply proves the service is up; an ICMP
	// port-unreachable (surfaced as ECONNREFUSED) proves the host is alive.
	confUDPOpen = 75
	confUDPLive = 78
	// TCP behaviour is a genuinely weak signal (we can't see SYN-ACK options from
	// a userspace connect) — kept low so it only ever corroborates, never wins.
	confTCPBehavior = 30
)
