package api

import (
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/tessera/tessera/internal/entity"
)

// TopoNode is one device in the topology tree, with the link that attaches it to
// its parent (port + speed) and its children below it.
type TopoNode struct {
	StableID string      `json:"stable_id"`
	Name     string      `json:"name"`
	IconURL  string      `json:"icon_url"`
	Sub      string      `json:"sub,omitempty"`   // model or device class
	Port     string      `json:"port,omitempty"`  // port on the parent
	Speed    string      `json:"speed,omitempty"` // link speed, formatted
	Children []*TopoNode `json:"children,omitempty"`
}

// TopologyView is the educated network map: roots (gateways/top switches) with
// their tree below, plus devices we couldn't place (no uplink/switch-port data).
type TopologyView struct {
	Roots    []*TopoNode `json:"roots"`
	Unplaced []*TopoNode `json:"unplaced"`
}

// handleTopology builds the device tree from the captured uplink / switch-port
// edges: each host attaches to the host that owns its parent MAC.
func (s *Server) handleTopology(w http.ResponseWriter, r *http.Request) {
	snap, err := s.store.LoadEntities(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	hostByID := map[int64]entity.Host{}
	for _, h := range snap.Hosts {
		hostByID[h.ID] = h
	}
	ifaceOwner := map[string]int64{} // normalized MAC → host id
	vendorByHost := map[int64]string{}
	for _, i := range snap.Interfaces {
		ifaceOwner[strings.ToLower(i.MAC)] = i.HostID
		if vendorByHost[i.HostID] == "" && i.OUIVendor != "" {
			vendorByHost[i.HostID] = i.OUIVendor
		}
	}

	type link struct{ parent int64; port, speed string }
	parent := map[int64]link{}
	for _, t := range snap.Topology {
		p, ok := ifaceOwner[strings.ToLower(t.Switch)]
		if !ok || p == t.HostID {
			continue // parent unknown (e.g. ISP modem) or self-link
		}
		if _, exists := parent[t.HostID]; !exists {
			parent[t.HostID] = link{p, t.SwitchPort, fmtLinkSpeed(t.Speed)}
		}
	}
	children := map[int64][]int64{}
	placed := map[int64]bool{}
	for child, l := range parent {
		children[l.parent] = append(children[l.parent], child)
		placed[child], placed[l.parent] = true, true
	}

	node := func(id int64, l link) *TopoNode {
		h := hostByID[id]
		_, url := s.effectiveIcon(h.Icon, vendorByHost[id], h.OSGuess, h.DeviceClass, h.Model)
		name := h.DisplayName
		if name == "" {
			name = h.StableID
		}
		sub := h.Model
		if sub == "" {
			sub = h.DeviceClass
		}
		return &TopoNode{StableID: h.StableID, Name: name, IconURL: url, Sub: sub, Port: l.port, Speed: l.speed}
	}
	// Recursive build with a visited guard against cycles.
	var build func(id int64, l link, seen map[int64]bool) *TopoNode
	build = func(id int64, l link, seen map[int64]bool) *TopoNode {
		n := node(id, l)
		if seen[id] {
			return n
		}
		seen[id] = true
		kids := children[id]
		sort.Slice(kids, func(i, j int) bool { return nodeName(hostByID[kids[i]]) < nodeName(hostByID[kids[j]]) })
		for _, c := range kids {
			n.Children = append(n.Children, build(c, parent[c], seen))
		}
		return n
	}

	var rootIDs []int64
	for id := range placed {
		if _, has := parent[id]; !has {
			rootIDs = append(rootIDs, id)
		}
	}
	sort.Slice(rootIDs, func(i, j int) bool { return nodeName(hostByID[rootIDs[i]]) < nodeName(hostByID[rootIDs[j]]) })
	out := TopologyView{Roots: []*TopoNode{}, Unplaced: []*TopoNode{}}
	for _, id := range rootIDs {
		out.Roots = append(out.Roots, build(id, link{}, map[int64]bool{}))
	}

	// Unplaced: hosts with no topology relationship at all (skip ignored).
	var unIDs []int64
	for _, h := range snap.Hosts {
		if !placed[h.ID] && !h.Ignored {
			unIDs = append(unIDs, h.ID)
		}
	}
	sort.Slice(unIDs, func(i, j int) bool { return nodeName(hostByID[unIDs[i]]) < nodeName(hostByID[unIDs[j]]) })
	for _, id := range unIDs {
		out.Unplaced = append(out.Unplaced, node(id, link{}))
	}
	writeJSON(w, http.StatusOK, out)
}

func nodeName(h entity.Host) string {
	if h.DisplayName != "" {
		return strings.ToLower(h.DisplayName)
	}
	return h.StableID
}

// fmtLinkSpeed turns a Mbps string into a human label (1000 → "1 GbE").
func fmtLinkSpeed(mbps string) string {
	n, err := strconv.Atoi(strings.TrimSpace(mbps))
	if err != nil || n <= 0 {
		return ""
	}
	switch n {
	case 10:
		return "10M"
	case 100:
		return "FE"
	case 1000:
		return "1 GbE"
	case 2500:
		return "2.5 GbE"
	case 5000:
		return "5 GbE"
	case 10000:
		return "10 GbE"
	case 25000:
		return "25 GbE"
	}
	if n%1000 == 0 {
		return strconv.Itoa(n/1000) + " GbE"
	}
	return strconv.Itoa(n) + " Mbps"
}
