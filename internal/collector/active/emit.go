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

	// Active mDNS mirrors the passive-sensor mDNS confidences (same classifiers):
	// a self-reported exact model outranks vendor fingerprints; a service type is
	// a solid class hint; an OS inferred from a service type is softer.
	confMDNSClass        = 55
	confMDNSOS           = 50
	confMDNSModel        = 88 // exact model= self-report (via the Apple model table)
	confMDNSModelGeneric = 70 // model= recognized only to device family
	confMDNSHost         = 74 // instance/host name from the device's own advertisement

	// Media identity probes (AirPlay /info, Cast eureka_info) are unauthenticated
	// first-party self-reports — strong, just under an exact mDNS model= match.
	confMediaClass = 78
	confMediaModel = 82
	confMediaOS    = 76
	confMediaName  = 74
)
