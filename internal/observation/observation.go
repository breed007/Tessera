// Package observation defines the append-only observation log — the one shape
// every collector writes in (§3.1). Nothing in the system talks to the entity
// tables directly; collectors emit Observations and the reconciler folds them.
package observation

import (
	"encoding/json"
	"fmt"
	"time"
)

// Source identifies the kind of signal that produced an observation (§3.1).
type Source string

const (
	SourcePassiveARP   Source = "passive_arp"
	SourcePassiveDHCP  Source = "passive_dhcp"
	SourcePassiveDHCP6 Source = "passive_dhcp6"
	SourcePassiveMDNS  Source = "passive_mdns"
	SourcePassiveSSDP  Source = "passive_ssdp"
	SourcePassiveNBNS  Source = "passive_netbios"
	SourcePassiveTLS   Source = "passive_tls_sni"
	SourceActiveICMP   Source = "active_icmp"
	SourceActiveARP    Source = "active_arp"
	SourceActiveTCP    Source = "active_tcp"
	SourceActiveUDP    Source = "active_udp"          // UDP service probe
	SourceActiveTCPBeh Source = "active_tcp_behavior" // TCP behavioural fingerprint
	SourceActiveRDNS   Source = "active_rdns"
	SourceActiveSNMP   Source = "active_snmp"
	SourceInferred     Source = "inferred" // reconciler's generic-inference layer
	SourceUniFi        Source = "unifi"
	SourceFingerbank   Source = "fingerbank"
	SourceManual       Source = "manual"
)

var validSources = map[Source]bool{
	SourcePassiveARP: true, SourcePassiveDHCP: true, SourcePassiveDHCP6: true,
	SourcePassiveMDNS: true, SourcePassiveSSDP: true, SourcePassiveNBNS: true,
	SourcePassiveTLS: true, SourceActiveICMP: true, SourceActiveARP: true,
	SourceActiveTCP: true, SourceActiveUDP: true, SourceActiveTCPBeh: true, SourceActiveRDNS: true,
	SourceActiveSNMP: true, SourceInferred: true,
	SourceUniFi: true, SourceFingerbank: true, SourceManual: true,
}

// SubjectType is what the subject identifier refers to (§3.1).
type SubjectType string

const (
	SubjectMAC  SubjectType = "mac"
	SubjectIPv4 SubjectType = "ipv4"
	SubjectIPv6 SubjectType = "ipv6"
	SubjectHost SubjectType = "host"
)

var validSubjectTypes = map[SubjectType]bool{
	SubjectMAC: true, SubjectIPv4: true, SubjectIPv6: true, SubjectHost: true,
}

// Attribute is the fact being asserted about the subject (§3.1). The enum is
// extensible; this is the starting set.
type Attribute string

const (
	AttrIPBinding       Attribute = "ip_binding"
	AttrLiveness        Attribute = "liveness"
	AttrHostname        Attribute = "hostname"
	AttrOUIVendor       Attribute = "oui_vendor"
	AttrDHCPFingerprint Attribute = "dhcp_fingerprint"
	AttrDHCPVendor      Attribute = "dhcp_vendor"
	AttrUserAgent       Attribute = "user_agent"
	AttrDeviceClass     Attribute = "device_class"
	AttrOSGuess         Attribute = "os_guess"
	AttrFirmware        Attribute = "firmware" // device firmware/version (e.g. UniFi gear)
	AttrOpenPort        Attribute = "open_port"
	AttrServiceBanner   Attribute = "service_banner"
	AttrTCPBehavior     Attribute = "tcp_behavior" // closed-port behaviour: rst_immediate|silent_drop|icmp_unreachable
	AttrSwitchPort      Attribute = "switch_port"
	AttrVLANMembership  Attribute = "vlan_membership"
	AttrSubnetHint      Attribute = "subnet_hint"
	AttrFirstSeen       Attribute = "first_seen"
	AttrLastSeen        Attribute = "last_seen"
	// Human-annotation attributes (§3.2). Written only by the manual source via
	// the API; authoritative in reconciliation.
	AttrIsExpected  Attribute = "is_expected"  // "true"/"false" — device is known/expected
	AttrNotes       Attribute = "notes"        // free-text operator note
	AttrReservation Attribute = "reservation"  // on an IP: "reserved"
	AttrDisplayName Attribute = "display_name" // operator-set host name
	AttrIcon        Attribute = "icon"         // operator-set device icon id (§M12)
)

var validAttributes = map[Attribute]bool{
	AttrIPBinding: true, AttrLiveness: true, AttrHostname: true, AttrOUIVendor: true,
	AttrDHCPFingerprint: true, AttrDHCPVendor: true, AttrUserAgent: true,
	AttrDeviceClass: true, AttrOSGuess: true, AttrFirmware: true, AttrOpenPort: true, AttrServiceBanner: true,
	AttrTCPBehavior: true,
	AttrSwitchPort:  true, AttrVLANMembership: true, AttrSubnetHint: true,
	AttrFirstSeen: true, AttrLastSeen: true,
	AttrIsExpected: true, AttrNotes: true, AttrReservation: true, AttrDisplayName: true, AttrIcon: true,
}

// Observation is one raw, immutable assertion in the append-only log. Every
// collector — passive, active, UniFi, Fingerbank, manual — produces exactly
// this shape. ID is assigned by the store on Append.
type Observation struct {
	ID          int64           `json:"id"`
	ObservedAt  time.Time       `json:"observed_at"`   // when the signal was seen (not when written)
	Source      Source          `json:"source"`        //
	CollectorID string          `json:"collector_id"`  // which sensor/poller instance produced it
	SubjectType SubjectType     `json:"subject_type"`  //
	Subject     string          `json:"subject"`       // normalized MAC / IP / host key
	Attribute   Attribute       `json:"attribute"`     //
	Value       string          `json:"value"`         // asserted value (text or JSON)
	Confidence  int             `json:"confidence"`    // 0–100, the collector's confidence in THIS assertion
	Raw         json.RawMessage `json:"raw,omitempty"` // optional original payload for audit/debug
}

// Validate checks enum membership and bounds. The store rejects observations
// that fail this so the log never holds malformed rows.
func (o Observation) Validate() error {
	if o.ObservedAt.IsZero() {
		return fmt.Errorf("observation: observed_at is zero")
	}
	if !validSources[o.Source] {
		return fmt.Errorf("observation: invalid source %q", o.Source)
	}
	if o.CollectorID == "" {
		return fmt.Errorf("observation: empty collector_id")
	}
	if !validSubjectTypes[o.SubjectType] {
		return fmt.Errorf("observation: invalid subject_type %q", o.SubjectType)
	}
	if o.Subject == "" {
		return fmt.Errorf("observation: empty subject")
	}
	if !validAttributes[o.Attribute] {
		return fmt.Errorf("observation: invalid attribute %q", o.Attribute)
	}
	if o.Confidence < 0 || o.Confidence > 100 {
		return fmt.Errorf("observation: confidence %d out of range 0-100", o.Confidence)
	}
	return nil
}
