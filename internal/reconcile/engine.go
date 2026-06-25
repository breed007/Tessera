package reconcile

import (
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tessera/tessera/internal/entity"
	"github.com/tessera/tessera/internal/netid"
	"github.com/tessera/tessera/internal/observation"
	"github.com/tessera/tessera/internal/oui"
)

// highValueAttrs are the attributes whose disagreements are recorded as
// conflicts (§3.3). device_class is the spec's example; os_guess is the other
// classification output worth surfacing.
var highValueAttrs = map[observation.Attribute]bool{
	observation.AttrDeviceClass: true,
	observation.AttrOSGuess:     true,
}

// randomizedConfidencePenalty scales down a host's classification confidence
// when its identity rests only on randomized (locally-administered) MACs (§6).
const randomizedConfidencePenalty = 0.6

// engine performs one full reconciliation: it consumes the observation log and
// produces an entity.Snapshot under the §3.3 rules. It is single-use per
// rebuild; now and the thresholds are fixed for the duration so the result is
// internally consistent.
type engine struct {
	now    time.Time
	params Params

	// first-pass identity resolution
	ownerCand map[string]*resolver // ip -> candidate ip_binding observations (value = mac)

	// second-pass accumulation, keyed by canonical host id ("mac:.." / "ip:..")
	hosts   map[string]*hostAcc
	ifaces  map[string]*ifaceAcc       // mac -> interface accumulator
	addrs   map[string]*addrAcc        // ip -> address accumulator
	svcs    map[string]*entity.Service // hostKey|proto|port -> service
	topo    map[string]*entity.Topology
	subnets map[string]*subnetAcc // cidr|vlan -> subnet accumulator
}

// subnetAcc accumulates a configured network (from subnet_hint observations,
// §4.3). Manual annotations win; otherwise the best source tier provides the
// metadata, while first/last seen span all supporting observations.
type subnetAcc struct {
	cidr      string
	vlan      *int
	name      string
	gateway   string
	source    string
	bestTier  Tier
	haveBest  bool
	firstSeen time.Time
	lastSeen  time.Time
}

type hostAcc struct {
	stableID  string
	macs      map[string]bool
	firstSeen time.Time
	lastSeen  time.Time
	attrs     map[observation.Attribute]*resolver
}

type ifaceAcc struct {
	mac        string
	hostKey    string
	randomized bool
	oui        *resolver
}

type addrAcc struct {
	ip        string
	version   int
	hostKey   string
	mac       string
	state     *resolver // for manual "reserved"
	dhcp      *resolver // DHCP lease class (reserved/dynamic) from the DHCP server
	newest    time.Time // newest supporting observation (drives aging)
	firstSeen time.Time
	lastSeen  time.Time
}

func newEngine(now time.Time, p Params) *engine {
	return &engine{
		now:       now,
		params:    p,
		ownerCand: map[string]*resolver{},
		hosts:     map[string]*hostAcc{},
		ifaces:    map[string]*ifaceAcc{},
		addrs:     map[string]*addrAcc{},
		svcs:      map[string]*entity.Service{},
		topo:      map[string]*entity.Topology{},
		subnets:   map[string]*subnetAcc{},
	}
}

// ── pass 1: current IP→MAC ownership ─────────────────────────────────────────

// observeBinding records an ip_binding candidate so pass 1 can pick the current
// owner MAC of each IP by effective confidence.
func (e *engine) observeBinding(obs observation.Observation) {
	if obs.Attribute != observation.AttrIPBinding || obs.SubjectType != observation.SubjectMAC {
		return
	}
	ip, _, err := netid.NormalizeIP(obs.Value)
	if err != nil {
		return
	}
	r := e.ownerCand[ip]
	if r == nil {
		r = &resolver{}
		e.ownerCand[ip] = r
	}
	r.add(e.score(obs))
}

// currentOwner returns the MAC that currently owns ip, if any. The binding is
// the highest effective-confidence ip_binding for that IP — handling DHCP
// reassignment (the most recent/strongest binding wins). The owner MAC is the
// observation's subject (ip_binding is keyed by MAC subject, IP value).
func (e *engine) currentOwner(ip string) (string, bool) {
	r := e.ownerCand[ip]
	if r == nil {
		return "", false
	}
	w, ok := r.winner()
	if !ok {
		return "", false
	}
	return w.obs.Subject, true
}

// hostKeyFor maps an observation's subject to its canonical host identity (§3.3):
// MAC is primary; an IP folds into its current owner MAC, else a provisional
// ip-keyed host.
func (e *engine) hostKeyFor(obs observation.Observation) (string, bool) {
	switch obs.SubjectType {
	case observation.SubjectMAC:
		return "mac:" + obs.Subject, true
	case observation.SubjectIPv4, observation.SubjectIPv6:
		if mac, ok := e.currentOwner(obs.Subject); ok {
			return "mac:" + mac, true
		}
		return "ip:" + obs.Subject, true
	default:
		return "", false
	}
}

// ── pass 2: accumulate ───────────────────────────────────────────────────────

func (e *engine) apply(obs observation.Observation) {
	// subnet_hint describes a network, not a host/address — fold it separately
	// (§4.3: configured networks seed the subnets table).
	if obs.Attribute == observation.AttrSubnetHint {
		e.applySubnet(obs)
		return
	}

	hk, ok := e.hostKeyFor(obs)
	if !ok {
		return
	}
	h := e.host(hk)
	touch(&h.firstSeen, &h.lastSeen, obs.ObservedAt)

	switch obs.SubjectType {
	case observation.SubjectMAC:
		e.applyMAC(h, obs)
	case observation.SubjectIPv4, observation.SubjectIPv6:
		e.applyIP(h, obs)
	}
}

func (e *engine) applyMAC(h *hostAcc, obs observation.Observation) {
	mac := obs.Subject
	h.macs[mac] = true
	iface := e.iface(mac, h.stableID)

	switch obs.Attribute {
	case observation.AttrIPBinding:
		ip, ver, err := netid.NormalizeIP(obs.Value)
		if err != nil {
			return
		}
		a := e.addr(ip, ver, h.stableID)
		a.mac = mac
		e.support(a, obs.ObservedAt)

	case observation.AttrOUIVendor:
		// §6: never trust a synthetic OUI from a randomized MAC.
		if !iface.randomized {
			iface.oui.add(e.score(obs))
		}

	case observation.AttrHostname, observation.AttrDeviceClass, observation.AttrOSGuess, observation.AttrFirmware, observation.AttrModel,
		observation.AttrDisplayName, observation.AttrIsExpected, observation.AttrIgnored, observation.AttrTags, observation.AttrNotes, observation.AttrIcon:
		e.hostAttr(h, obs)

	case observation.AttrSwitchPort:
		e.applyTopology(h, obs)
	case observation.AttrVLANMembership:
		e.applyVLAN(h, obs)
	}
}

func (e *engine) applyIP(h *hostAcc, obs observation.Observation) {
	ip, ver, err := netid.NormalizeIP(obs.Subject)
	if err != nil {
		return
	}
	a := e.addr(ip, ver, h.stableID)

	switch obs.Attribute {
	case observation.AttrLiveness, observation.AttrFirstSeen, observation.AttrLastSeen:
		e.support(a, obs.ObservedAt)
	case observation.AttrHostname:
		e.hostAttr(h, obs)
		e.support(a, obs.ObservedAt)
	case observation.AttrDeviceClass, observation.AttrOSGuess, observation.AttrTCPBehavior, observation.AttrModel,
		observation.AttrDisplayName, observation.AttrIsExpected, observation.AttrIgnored, observation.AttrTags, observation.AttrNotes, observation.AttrIcon:
		// IP-subject classification (SNMP), behavioural fingerprint, and IP-keyed
		// manual annotations.
		e.hostAttr(h, obs)
	case observation.AttrReservation:
		// Manual reservation of an address (§3.2); folded by ageState.
		a.state.add(e.score(obs))
		e.support(a, obs.ObservedAt)
	case observation.AttrDHCPLease:
		// DHCP server's lease class (reserved/dynamic); keeps the address alive too.
		a.dhcp.add(e.score(obs))
		e.support(a, obs.ObservedAt)
	case observation.AttrOpenPort:
		e.support(a, obs.ObservedAt)
		e.applyService(h, obs)
	case observation.AttrServiceBanner:
		e.support(a, obs.ObservedAt)
		e.applyBanner(h, obs)
	case observation.AttrIPBinding:
		// IP-subject binding (value = mac); already handled in pass 1 ownership.
		e.support(a, obs.ObservedAt)
	}
}

// ── accessors ────────────────────────────────────────────────────────────────

func (e *engine) host(key string) *hostAcc {
	h := e.hosts[key]
	if h == nil {
		h = &hostAcc{stableID: key, macs: map[string]bool{}, attrs: map[observation.Attribute]*resolver{}}
		e.hosts[key] = h
	}
	return h
}

func (e *engine) hostAttr(h *hostAcc, obs observation.Observation) {
	r := h.attrs[obs.Attribute]
	if r == nil {
		r = &resolver{}
		h.attrs[obs.Attribute] = r
	}
	r.add(e.score(obs))
}

func (e *engine) iface(mac, hostKey string) *ifaceAcc {
	i := e.ifaces[mac]
	if i == nil {
		i = &ifaceAcc{mac: mac, hostKey: hostKey, randomized: netid.IsLocallyAdministered(mac), oui: &resolver{}}
		e.ifaces[mac] = i
	}
	return i
}

func (e *engine) addr(ip string, ver int, hostKey string) *addrAcc {
	a := e.addrs[ip]
	if a == nil {
		a = &addrAcc{ip: ip, version: ver, hostKey: hostKey, state: &resolver{}, dhcp: &resolver{}}
		e.addrs[ip] = a
	}
	// Re-home the address to the latest resolved host key (current owner).
	a.hostKey = hostKey
	return a
}

// support records that an observation at t keeps the address alive; tracks the
// newest supporting timestamp (for aging) and first/last seen.
func (e *engine) support(a *addrAcc, t time.Time) {
	if t.After(a.newest) {
		a.newest = t
	}
	touch(&a.firstSeen, &a.lastSeen, t)
}

func (e *engine) applyService(h *hostAcc, obs observation.Observation) {
	proto, port, ok := parseProtoPort(obs.Value)
	if !ok {
		return
	}
	key := h.stableID + "|" + proto + "|" + strconv.Itoa(port)
	if _, exists := e.svcs[key]; !exists {
		e.svcs[key] = &entity.Service{Proto: proto, Port: port, Source: string(obs.Source)}
	}
	if obs.ObservedAt.After(e.svcs[key].LastSeen) {
		e.svcs[key].LastSeen = obs.ObservedAt
		e.svcs[key].Source = string(obs.Source)
	}
}

// applyBanner attaches a service banner (from the active prober) to its service.
// The value is encoded "<proto>/<port>|<banner>"; the service is created if the
// open_port observation hasn't been folded yet.
func (e *engine) applyBanner(h *hostAcc, obs observation.Observation) {
	head, banner, found := strings.Cut(obs.Value, "|")
	if !found {
		return
	}
	proto, port, ok := parseProtoPort(head)
	if !ok {
		return
	}
	key := h.stableID + "|" + proto + "|" + strconv.Itoa(port)
	svc := e.svcs[key]
	if svc == nil {
		svc = &entity.Service{Proto: proto, Port: port, Source: string(obs.Source)}
		e.svcs[key] = svc
	}
	// Take the banner from the newest observation that carries one (independent
	// of the open_port that may have set LastSeen at the same instant).
	if svc.Banner == "" || obs.ObservedAt.After(svc.LastSeen) {
		svc.Banner = banner
	}
	if obs.ObservedAt.After(svc.LastSeen) {
		svc.LastSeen = obs.ObservedAt
	}
}

func (e *engine) applyTopology(h *hostAcc, obs observation.Observation) {
	sw, port, speed := splitSwitchPort(obs.Value)
	key := h.stableID + "|" + sw + "|" + port
	t := e.topo[key]
	if t == nil {
		t = &entity.Topology{Switch: sw, SwitchPort: port, Speed: speed, Source: string(obs.Source)}
		e.topo[key] = t
	} else if speed != "" {
		t.Speed = speed
	}
}

// applySubnet folds a subnet_hint into the subnets accumulator, keyed by
// (cidr, vlan). Manual annotations are authoritative; otherwise the lowest
// (best) source tier supplies the metadata.
func (e *engine) applySubnet(obs observation.Observation) {
	hint, err := observation.ParseSubnetHint(obs.Value)
	if err != nil || hint.CIDR == "" {
		return
	}
	key := hint.CIDR + "|" + vlanKey(hint.VLAN)
	acc := e.subnets[key]
	if acc == nil {
		acc = &subnetAcc{cidr: hint.CIDR, vlan: hint.VLAN}
		e.subnets[key] = acc
	}
	touch(&acc.firstSeen, &acc.lastSeen, obs.ObservedAt)

	isManual := obs.Source == observation.SourceManual
	tier := tierFor(obs)
	if !acc.haveBest || isManual || tier < acc.bestTier {
		acc.name = hint.Name
		acc.gateway = hint.Gateway
		acc.source = string(obs.Source)
		acc.bestTier = tier
		acc.vlan = hint.VLAN
		acc.haveBest = true
	}
}

func (e *engine) applyVLAN(h *hostAcc, obs observation.Observation) {
	v, err := strconv.Atoi(strings.TrimSpace(obs.Value))
	if err != nil {
		return
	}
	// Attach the VLAN to any topology rows for this host (best effort, M3.5
	// finalizes the UniFi mapping).
	for key, t := range e.topo {
		if strings.HasPrefix(key, h.stableID+"|") {
			vv := v
			t.VLAN = &vv
		}
	}
}

func (e *engine) score(obs observation.Observation) scored {
	return scored{
		obs:  obs,
		eff:  effective(obs.Confidence, obs.ObservedAt, e.now, e.params.ConfidenceHalfLife),
		tier: tierFor(obs),
	}
}

// ── finalize: build the deterministic snapshot ───────────────────────────────

func (e *engine) snapshot() (entity.Snapshot, []conflictRec) {
	var snap entity.Snapshot
	var conflicts []conflictRec

	// Subnets first: addresses below resolve their subnet_id by membership.
	subnetKeys := sortedKeys(e.subnets)
	var members []subnetMember
	for i, k := range subnetKeys {
		s := e.subnets[k]
		id := int64(i + 1)
		snap.Subnets = append(snap.Subnets, entity.Subnet{
			ID:        id,
			CIDR:      s.cidr,
			VLANID:    s.vlan,
			Name:      s.name,
			Source:    s.source,
			Gateway:   s.gateway,
			FirstSeen: s.firstSeen,
			LastSeen:  s.lastSeen,
		})
		if _, ipnet, err := net.ParseCIDR(s.cidr); err == nil && ipnet != nil {
			members = append(members, subnetMember{id: id, net: ipnet})
		}
	}

	// Stable host ids: sort by stable_id.
	hostKeys := sortedKeys(e.hosts)
	hostID := map[string]int64{}
	for i, k := range hostKeys {
		hostID[k] = int64(i + 1)
	}

	// Per-host open ports & banners (inputs for the generic-inference layer).
	portsByHost := map[string][]int{}
	bannersByHost := map[string][]string{}
	for key, sv := range e.svcs {
		hk := strings.SplitN(key, "|", 2)[0]
		if sv.Proto == "tcp" {
			portsByHost[hk] = append(portsByHost[hk], sv.Port)
		}
		if sv.Banner != "" {
			bannersByHost[hk] = append(bannersByHost[hk], sv.Banner)
		}
	}

	for _, k := range hostKeys {
		h := e.hosts[k]
		host := entity.Host{
			ID:        hostID[k],
			StableID:  h.stableID,
			FirstSeen: h.firstSeen,
			LastSeen:  h.lastSeen,
		}
		// Display name: an explicit manual display_name annotation wins; otherwise
		// fall back to the best discovered hostname.
		if w, ok := winnerValue(h.attrs[observation.AttrDisplayName]); ok {
			host.DisplayName = w
		} else if w, ok := winnerValue(h.attrs[observation.AttrHostname]); ok {
			host.DisplayName = w
		}
		// Human annotations (§3.2): authoritative, manual-only in practice.
		if w, ok := winnerValue(h.attrs[observation.AttrIsExpected]); ok {
			host.IsExpected = w == "true"
		}
		if w, ok := winnerValue(h.attrs[observation.AttrIgnored]); ok {
			host.Ignored = w == "true"
		}
		if w, ok := winnerValue(h.attrs[observation.AttrTags]); ok && w != "" {
			host.Tags = strings.Split(w, ",")
		}
		if w, ok := winnerValue(h.attrs[observation.AttrNotes]); ok {
			host.Notes = w
		}
		if w, ok := winnerValue(h.attrs[observation.AttrIcon]); ok {
			host.Icon = w
		}
		if w, ok := winnerValue(h.attrs[observation.AttrFirmware]); ok {
			host.Firmware = w
		}
		if w, ok := winnerValue(h.attrs[observation.AttrModel]); ok {
			host.Model = w
		}
		if s, ok := winnerScored(h.attrs[observation.AttrDeviceClass]); ok {
			host.DeviceClass = s.obs.Value
			host.Confidence = clampConf(s.eff * e.randomizedFactor(h))
		}
		if s, ok := winnerScored(h.attrs[observation.AttrOSGuess]); ok {
			host.OSGuess = s.obs.Value
			if host.Confidence == 0 {
				host.Confidence = clampConf(s.eff * e.randomizedFactor(h))
			}
		}
		// Generic inference (§6): for anything the authoritative collectors left
		// unclassified, derive a Hardware/Device and OS from the weak signals and
		// fill only the gaps. Capped low, so a real signal is never overridden.
		if host.DeviceClass == "" || host.OSGuess == "" {
			res := inferIdentity(inferInput{
				openPorts:   portsByHost[k],
				banners:     bannersByHost[k],
				vendor:      e.hostVendor(h),
				hostname:    inferHostname(h),
				dhcpVendor:  hostAttrValue(h, observation.AttrDHCPVendor),
				tcpBehavior: hostAttrValue(h, observation.AttrTCPBehavior),
			})
			if host.DeviceClass == "" && res.deviceClass != "" {
				host.DeviceClass = res.deviceClass
				if host.Confidence == 0 {
					host.Confidence = res.deviceConf
				}
			}
			if host.OSGuess == "" && res.osGuess != "" {
				host.OSGuess = res.osGuess
				if host.Confidence == 0 {
					host.Confidence = res.osConf
				}
			}
		}
		// Record conflicts on the high-value attributes.
		for attr := range highValueAttrs {
			conflicts = append(conflicts, e.collectConflicts(h.stableID, h.attrs[attr])...)
		}
		snap.Hosts = append(snap.Hosts, host)
	}

	// Interfaces: sort by mac.
	ifaceMacs := sortedKeys(e.ifaces)
	for i, mac := range ifaceMacs {
		ia := e.ifaces[mac]
		iface := entity.Interface{
			ID:           int64(i + 1),
			HostID:       hostID[ia.hostKey],
			MAC:          mac,
			IsRandomized: ia.randomized,
		}
		if v, ok := winnerValue(ia.oui); ok {
			iface.OUIVendor = v
		} else if !iface.IsRandomized {
			// Offline OUI fallback (§7): always-available vendor attribution that
			// depends on no external service. Skipped for randomized MACs (§6).
			if v, ok := oui.Lookup(mac); ok {
				iface.OUIVendor = v
			}
		}
		snap.Interfaces = append(snap.Interfaces, iface)
	}

	// Addresses: sort by (version, ip).
	addrIPs := sortedKeys(e.addrs)
	sort.SliceStable(addrIPs, func(i, j int) bool {
		ai, aj := e.addrs[addrIPs[i]], e.addrs[addrIPs[j]]
		if ai.version != aj.version {
			return ai.version < aj.version
		}
		return ai.ip < aj.ip
	})
	for i, ip := range addrIPs {
		a := e.addrs[ip]
		addr := entity.Address{
			ID:        int64(i + 1),
			IP:        a.ip,
			IPVersion: a.version,
			MAC:       a.mac,
			State:     e.ageState(a),
			FirstSeen: a.firstSeen,
			LastSeen:  a.lastSeen,
		}
		if w, ok := a.dhcp.winner(); ok {
			addr.DHCP = w.obs.Value
		}
		if id, ok := hostID[a.hostKey]; ok {
			addr.HostID = &id
		}
		if sid, ok := subnetForIP(a.ip, members); ok {
			addr.SubnetID = &sid
		}
		snap.Addresses = append(snap.Addresses, addr)
	}

	// Services & topology, deterministically ordered.
	for _, key := range sortedKeys(e.svcs) {
		sv := *e.svcs[key]
		hk := strings.SplitN(key, "|", 2)[0]
		if id, ok := hostID[hk]; ok {
			sv.HostID = &id
		}
		sv.ID = int64(len(snap.Services) + 1)
		snap.Services = append(snap.Services, sv)
	}
	for _, key := range sortedKeys(e.topo) {
		tp := *e.topo[key]
		hk := strings.SplitN(key, "|", 2)[0]
		tp.HostID = hostID[hk]
		tp.ID = int64(len(snap.Topology) + 1)
		snap.Topology = append(snap.Topology, tp)
	}

	return snap, conflicts
}

// ageState transitions an address active→stale→free by the age of its newest
// supporting observation (§3.3). reserved is a manual annotation.
func (e *engine) ageState(a *addrAcc) entity.AddressState {
	if w, ok := a.state.winner(); ok && w.obs.Source == observation.SourceManual && w.obs.Value == "reserved" {
		return entity.StateReserved
	}
	if a.newest.IsZero() {
		return entity.StateFree
	}
	age := e.now.Sub(a.newest)
	switch {
	case age <= e.params.StaleAfter:
		return entity.StateActive
	case age <= e.params.FreeAfter:
		return entity.StateStale
	default:
		return entity.StateFree
	}
}

// hostVendor returns the best OUI vendor across a host's interfaces — a resolved
// oui_vendor observation if present, else the offline OUI table — for inference.
func (e *engine) hostVendor(h *hostAcc) string {
	macs := make([]string, 0, len(h.macs))
	for mac := range h.macs {
		macs = append(macs, mac)
	}
	sort.Strings(macs)
	for _, mac := range macs {
		ia := e.ifaces[mac]
		if ia == nil || ia.randomized {
			continue
		}
		if v, ok := winnerValue(ia.oui); ok && v != "" {
			return v
		}
		if v, ok := oui.Lookup(mac); ok && v != "" {
			return v
		}
	}
	return ""
}

// inferHostname returns the best discovered hostname for inference (the resolved
// hostname observation; not a manual display_name, which carries no device hint).
func inferHostname(h *hostAcc) string {
	v, _ := winnerValue(h.attrs[observation.AttrHostname])
	return v
}

// hostAttrValue returns the winning value of a host attribute, or "".
func hostAttrValue(h *hostAcc, attr observation.Attribute) string {
	v, _ := winnerValue(h.attrs[attr])
	return v
}

// randomizedFactor down-weights classification confidence for hosts whose
// identity rests only on randomized MACs (§6).
func (e *engine) randomizedFactor(h *hostAcc) float64 {
	if len(h.macs) == 0 {
		return 1
	}
	for mac := range h.macs {
		if !netid.IsLocallyAdministered(mac) {
			return 1 // at least one globally-unique MAC → trust normally
		}
	}
	return randomizedConfidencePenalty
}

type conflictRec struct {
	subject   string
	attribute string
	valueA    string
	sourceA   string
	valueB    string
	sourceB   string
	openedAt  time.Time
}

func (e *engine) collectConflicts(subject string, r *resolver) []conflictRec {
	if r == nil {
		return nil
	}
	w, ok := r.winner()
	if !ok {
		return nil
	}
	alt, ok := r.conflict(w)
	if !ok {
		return nil
	}
	opened := w.obs.ObservedAt
	if alt.obs.ObservedAt.After(opened) {
		opened = alt.obs.ObservedAt
	}
	return []conflictRec{{
		subject:   subject,
		attribute: string(w.obs.Attribute),
		valueA:    w.obs.Value,
		sourceA:   string(w.obs.Source),
		valueB:    alt.obs.Value,
		sourceB:   string(alt.obs.Source),
		openedAt:  opened,
	}}
}

// ── small helpers ────────────────────────────────────────────────────────────

// subnetMember pairs a subnet id with its parsed network for membership tests.
type subnetMember struct {
	id  int64
	net *net.IPNet
}

// subnetForIP returns the id of the most-specific (longest-prefix) subnet that
// contains ip, if any.
func subnetForIP(ip string, members []subnetMember) (int64, bool) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return 0, false
	}
	var bestID int64
	bestOnes := -1
	found := false
	for _, m := range members {
		if !m.net.Contains(parsed) {
			continue
		}
		ones, _ := m.net.Mask.Size()
		if ones > bestOnes {
			bestOnes, bestID, found = ones, m.id, true
		}
	}
	return bestID, found
}

// vlanKey renders an optional VLAN id as a stable map-key fragment.
func vlanKey(v *int) string {
	if v == nil {
		return "-"
	}
	return strconv.Itoa(*v)
}

func touch(first, last *time.Time, t time.Time) {
	if first.IsZero() || t.Before(*first) {
		*first = t
	}
	if t.After(*last) {
		*last = t
	}
}

func winnerValue(r *resolver) (string, bool) {
	if r == nil {
		return "", false
	}
	w, ok := r.winner()
	if !ok {
		return "", false
	}
	return w.obs.Value, true
}

func winnerScored(r *resolver) (scored, bool) {
	if r == nil {
		return scored{}, false
	}
	return r.winner()
}

func clampConf(f float64) int {
	v := int(f + 0.5)
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// sortedKeys returns the map keys in ascending string order (deterministic).
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// parseProtoPort parses an open_port value of the form "tcp/22" or "22"
// (proto defaults to tcp). This is the agreed encoding the M4 prober emits.
func parseProtoPort(v string) (proto string, port int, ok bool) {
	v = strings.TrimSpace(v)
	proto = "tcp"
	if i := strings.IndexByte(v, '/'); i >= 0 {
		proto = strings.ToLower(v[:i])
		v = v[i+1:]
	}
	p, err := strconv.Atoi(v)
	if err != nil || p <= 0 || p > 65535 {
		return "", 0, false
	}
	return proto, p, true
}

// splitSwitchPort splits a switch_port value "switchName/portIdx" on the last
// slash. The M3.5 UniFi poller emits this encoding.
func splitSwitchPort(v string) (sw, port, speed string) {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, '|'); i >= 0 { // optional "|<mbps>" speed suffix
		speed, v = v[i+1:], v[:i]
	}
	if i := strings.LastIndexByte(v, '/'); i >= 0 {
		return v[:i], v[i+1:], speed
	}
	return v, "", speed
}
