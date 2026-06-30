package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/tessera/tessera/internal/netid"
	"github.com/tessera/tessera/internal/observation"
)

// createHostRequest documents a device by hand (offline gear, planned kit) by
// seeding manual observations the reconciler materializes into a host. A MAC is
// required — it's the stable identity. Manually-added hosts are marked Expected.
type createHostRequest struct {
	MAC         string `json:"mac"`
	IP          string `json:"ip,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	DeviceClass string `json:"device_class,omitempty"`
	Model       string `json:"model,omitempty"`
	Notes       string `json:"notes,omitempty"`
}

func (s *Server) handleCreateHost(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	var req createHostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON")
		return
	}
	mac, err := netid.NormalizeMAC(req.MAC)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "a valid MAC is required")
		return
	}
	ctx := r.Context()
	rec := func(attr observation.Attribute, value string, conf int) bool {
		if _, err := s.sink.Record(ctx, observation.SourceManual, observation.SubjectMAC, mac, attr, value, conf); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return false
		}
		return true
	}
	warning := ""
	if ip := strings.TrimSpace(req.IP); ip != "" {
		norm, _, err := netid.NormalizeIP(ip)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad ip")
			return
		}
		// Documenting a device must NOT yank an in-use IP off the real host. If the
		// IP is already owned by another device, skip the binding and warn; the
		// address materializes on this host only when the IP is genuinely free.
		if owner, ok := s.ipOwner(ctx, norm); ok && owner != "mac:"+mac {
			warning = "IP " + norm + " is currently assigned to another device (" + owner + "); the device was added without it."
		} else if !rec(observation.AttrIPBinding, norm, manualBindingConfidence) {
			return
		}
	}
	if v := strings.TrimSpace(req.DisplayName); v != "" && !rec(observation.AttrDisplayName, v, manualConfidence) {
		return
	}
	if v := strings.TrimSpace(req.DeviceClass); v != "" && !rec(observation.AttrDeviceClass, v, manualConfidence) {
		return
	}
	if v := strings.TrimSpace(req.Model); v != "" && !rec(observation.AttrModel, v, manualConfidence) {
		return
	}
	if v := strings.TrimSpace(req.Notes); v != "" && !rec(observation.AttrNotes, v, manualConfidence) {
		return
	}
	// A hand-added device is one the operator already knows about.
	if !rec(observation.AttrIsExpected, "true", manualConfidence) {
		return
	}
	s.reconcileNow(ctx)
	resp := map[string]any{"ok": true, "stable_id": "mac:" + mac}
	if warning != "" {
		resp["warning"] = warning
	}
	writeJSON(w, http.StatusOK, resp)
}

// manualBindingConfidence keeps a hand-entered IP↔MAC binding well below any live
// discovery (~90–95) so documenting a device never steals an in-use address.
const manualBindingConfidence = 50

// ipOwner returns the stable_id of the host currently holding an IP, if any.
func (s *Server) ipOwner(ctx context.Context, ip string) (string, bool) {
	snap, err := s.store.LoadEntities(ctx)
	if err != nil {
		return "", false
	}
	stableByID := map[int64]string{}
	for _, h := range snap.Hosts {
		stableByID[h.ID] = h.StableID
	}
	for _, a := range snap.Addresses {
		if a.IP == ip && a.HostID != nil {
			return stableByID[*a.HostID], true
		}
	}
	return "", false
}

// createSubnetRequest documents a network by hand. Seeds a manual subnet_hint.
type createSubnetRequest struct {
	CIDR string `json:"cidr"`
	Name string `json:"name,omitempty"`
	VLAN *int   `json:"vlan,omitempty"`
}

func (s *Server) handleCreateSubnet(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	var req createSubnetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON")
		return
	}
	_, ipnet, err := net.ParseCIDR(strings.TrimSpace(req.CIDR))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "a valid CIDR is required (e.g. 10.0.0.0/24)")
		return
	}
	network := ipnet.IP.String()
	styp := observation.SubjectIPv4
	if ipnet.IP.To4() == nil {
		styp = observation.SubjectIPv6
	}
	val := observation.SubnetHintValue{CIDR: ipnet.String(), Name: strings.TrimSpace(req.Name), VLAN: req.VLAN}.MarshalValue()
	if _, err := s.sink.Record(r.Context(), observation.SourceManual, styp, network, observation.AttrSubnetHint, val, manualConfidence); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.reconcileNow(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cidr": ipnet.String()})
}
