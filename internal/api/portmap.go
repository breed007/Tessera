package api

import (
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/tessera/tessera/internal/collector/unifi"
	"github.com/tessera/tessera/internal/entity"
)

// PortSlot is one physical port on a switch: empty, or the device patched into it.
type PortSlot struct {
	Port     int    `json:"port"`
	Device   string `json:"device,omitempty"`
	StableID string `json:"stable_id,omitempty"`
	Speed    string `json:"speed,omitempty"`
	VLAN     *int   `json:"vlan,omitempty"`
}

// SwitchPorts is a switch's faceplate: every port 1..Total, with occupants filled.
type SwitchPorts struct {
	StableID string     `json:"stable_id"`
	Name     string     `json:"name"`
	Model    string     `json:"model,omitempty"`
	IconURL  string     `json:"icon_url"`
	Total    int        `json:"total"`
	Used     int        `json:"used"`
	Ports    []PortSlot `json:"ports"`
}

// PortmapView is the patch-panel page: one faceplate per port-bearing device.
type PortmapView struct {
	Switches []SwitchPorts `json:"switches"`
}

// handlePortmap builds a per-switch port map from the topology edges (each child
// records the parent switch MAC + numeric port). Total port count comes from the
// bundled model DB so empty ports render too.
func (s *Server) handlePortmap(w http.ResponseWriter, r *http.Request) {
	snap, err := s.store.LoadEntities(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	hostByID := map[int64]entity.Host{}
	for _, h := range snap.Hosts {
		hostByID[h.ID] = h
	}
	ifaceOwner := map[string]int64{}
	vendorByHost := map[int64]string{}
	for _, i := range snap.Interfaces {
		ifaceOwner[strings.ToLower(i.MAC)] = i.HostID
		if vendorByHost[i.HostID] == "" {
			vendorByHost[i.HostID] = i.OUIVendor
		}
	}

	// parentID → port → slot.
	occ := map[int64]map[int]PortSlot{}
	for _, t := range snap.Topology {
		port, err := strconv.Atoi(t.SwitchPort)
		if err != nil {
			continue // non-numeric (e.g. "wifi") — not a switch port
		}
		parent, ok := ifaceOwner[strings.ToLower(t.Switch)]
		if !ok {
			continue
		}
		child := hostByID[t.HostID]
		if occ[parent] == nil {
			occ[parent] = map[int]PortSlot{}
		}
		if _, taken := occ[parent][port]; taken {
			continue
		}
		occ[parent][port] = PortSlot{Port: port, Device: hostLabel(child), StableID: child.StableID, Speed: fmtLinkSpeed(t.Speed), VLAN: t.VLAN}
	}

	out := PortmapView{Switches: []SwitchPorts{}}
	for id, ports := range occ {
		h := hostByID[id]
		total, ok := unifi.PortCount(h.Model)
		if !ok {
			for p := range ports { // fall back to the highest occupied port
				if p > total {
					total = p
				}
			}
		}
		_, icon := s.effectiveIcon(h.Icon, vendorByHost[id], h.OSGuess, h.DeviceClass, h.Model)
		sw := SwitchPorts{StableID: h.StableID, Name: hostLabel(h), Model: h.Model, IconURL: icon, Total: total, Used: len(ports)}
		for p := 1; p <= total; p++ {
			if slot, taken := ports[p]; taken {
				sw.Ports = append(sw.Ports, slot)
			} else {
				sw.Ports = append(sw.Ports, PortSlot{Port: p})
			}
		}
		out.Switches = append(out.Switches, sw)
	}
	sort.Slice(out.Switches, func(i, j int) bool { return out.Switches[i].Name < out.Switches[j].Name })
	writeJSON(w, http.StatusOK, out)
}
