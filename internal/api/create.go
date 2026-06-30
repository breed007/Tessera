package api

import (
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
	rec := func(attr observation.Attribute, value string) bool {
		if _, err := s.sink.Record(ctx, observation.SourceManual, observation.SubjectMAC, mac, attr, value, manualConfidence); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return false
		}
		return true
	}
	if ip := strings.TrimSpace(req.IP); ip != "" {
		norm, _, err := netid.NormalizeIP(ip)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad ip")
			return
		}
		if !rec(observation.AttrIPBinding, norm) {
			return
		}
	}
	if v := strings.TrimSpace(req.DisplayName); v != "" && !rec(observation.AttrDisplayName, v) {
		return
	}
	if v := strings.TrimSpace(req.DeviceClass); v != "" && !rec(observation.AttrDeviceClass, v) {
		return
	}
	if v := strings.TrimSpace(req.Model); v != "" && !rec(observation.AttrModel, v) {
		return
	}
	if v := strings.TrimSpace(req.Notes); v != "" && !rec(observation.AttrNotes, v) {
		return
	}
	// A hand-added device is one the operator already knows about.
	if !rec(observation.AttrIsExpected, "true") {
		return
	}
	s.reconcileNow(ctx)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "stable_id": "mac:" + mac})
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
