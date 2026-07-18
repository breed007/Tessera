package passive

// Exported wrappers so the active prober's mDNS querier can reuse the exact same
// DNS-SD classification the passive sensor uses — one source of truth for "what
// does _airplay / model=Mac16,7 mean", whether the record arrived via SPAN
// capture or via an active unicast mDNS query.

// ClassifyMDNSService maps a DNS-SD service type (e.g. "_airplay") to a device
// class and (rarely) an OS.
func ClassifyMDNSService(svc string) (dev, os string) { return classifyMDNSService(svc) }

// ClassifyMDNSModel maps a TXT model= value to a device string, OS, and whether
// the match was an exact marketing-name resolution (precise) vs a coarse family.
func ClassifyMDNSModel(model string) (dev, os string, precise bool) { return classifyMDNSModel(model) }

// MDNSServiceLabel extracts the "_app" service label from a DNS-SD name, e.g.
// "Lounge._airplay._tcp.local" → "_airplay". Returns "" if not a DNS-SD name.
func MDNSServiceLabel(name string) string { return mdnsService(name) }
