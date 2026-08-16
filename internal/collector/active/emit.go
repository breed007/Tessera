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
	// The release is a direct read of (or arithmetic on) the device's own build
	// string — a firmer statement than the family name inferred alongside it, and
	// on the same footing as an exact model= self-report.
	confMediaOSVersion = 88
)

// NTLM: a CHALLENGE is the host's own statement of what it runs, and only a
// Windows (or Samba) stack answers one at all — so the family is firm and the
// build, read straight out of the message, firmer still. The hostname is the
// machine's configured name, on a par with an mDNS self-report.
const (
	confNTLMOS        = 86
	confNTLMOSVersion = 90
	confNTLMHost      = 78
)

// Proxmox VE: the login page names the product outright and states its own
// version, so both are near-certain. The class is an inference from the product
// (a hypervisor is a server) and sits lower. The node name is the hypervisor's
// own, on a par with other first-party names.
const (
	confPVEOS      = 90
	confPVEVersion = 90
	confPVEClass   = 80
	confPVEHost    = 84
)

// ESPHome: answering /events proves the firmware outright. The class derived
// from the ENTITY SET is structural — not editable without reflashing — so it
// is nearly as firm; the fallback "IoT device" is true but says little. The
// title is the owner's label and freely editable, so it stays a soft hostname.
const (
	confESPHomeOS      = 88
	confESPHomeClass   = 78
	confESPHomeGeneric = 60
	confESPHomeName    = 55
)

// lockdownd on 62078: strong, but held below the first-party self-reports
// (78–88) on purpose. Those read a device's own statement of what it is; this
// infers a family from a listening port, and 62078 sits inside the ephemeral
// range Windows allocates from, so a coincidental listener is possible. High
// enough to beat a vendor's guess, low enough that an AirPlay /info or an exact
// mDNS model= still wins.
const (
	confLockdownClass = 72
	confLockdownOS    = 72
)
