package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/tessera/tessera/internal/netid"
	"github.com/tessera/tessera/internal/observation"
)

// manualConfidence: human annotations are authoritative (§3.2); they enter the
// log at full confidence and the reconciler's manual-wins rule keeps them
// current regardless of any discovered value.
const manualConfidence = 100

// annotateRequest is the body of POST /api/host/annotate. Only the provided
// fields are written; omitted fields are left untouched.
type annotateRequest struct {
	StableID    string  `json:"stable_id"`
	DisplayName *string `json:"display_name,omitempty"`
	DeviceClass *string `json:"device_class,omitempty"`
	Model       *string   `json:"model,omitempty"`
	IsExpected  *bool     `json:"is_expected,omitempty"`
	Ignored     *bool     `json:"ignored,omitempty"`
	Tags        *[]string `json:"tags,omitempty"`
	Notes       *string   `json:"notes,omitempty"`
	Icon        *string `json:"icon,omitempty"` // icon id; "" reverts to auto (§M12)
}

func (s *Server) handleAnnotate(w http.ResponseWriter, r *http.Request) {
	who, ok := s.requireOperator(w, r)
	if !ok {
		return
	}
	var req annotateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON")
		return
	}
	subjectType, subject, err := subjectFromStableID(req.StableID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx := r.Context()
	rec := func(attr observation.Attribute, value string) bool {
		if _, err := s.sink.Record(ctx, observation.SourceManual, subjectType, subject, attr, value, manualConfidence); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return false
		}
		return true
	}

	wrote := false
	if req.DisplayName != nil {
		if !rec(observation.AttrDisplayName, *req.DisplayName) {
			return
		}
		wrote = true
	}
	if req.DeviceClass != nil {
		if !rec(observation.AttrDeviceClass, *req.DeviceClass) {
			return
		}
		wrote = true
	}
	if req.Model != nil {
		if !rec(observation.AttrModel, *req.Model) {
			return
		}
		wrote = true
	}
	if req.IsExpected != nil {
		if !rec(observation.AttrIsExpected, boolString(*req.IsExpected)) {
			return
		}
		wrote = true
	}
	if req.Ignored != nil {
		if !rec(observation.AttrIgnored, boolString(*req.Ignored)) {
			return
		}
		wrote = true
	}
	if req.Tags != nil {
		// Normalize: trim, drop empties and commas (the storage delimiter).
		clean := make([]string, 0, len(*req.Tags))
		for _, t := range *req.Tags {
			t = strings.ReplaceAll(strings.TrimSpace(t), ",", " ")
			if t != "" {
				clean = append(clean, t)
			}
		}
		if !rec(observation.AttrTags, strings.Join(clean, ",")) {
			return
		}
		wrote = true
	}
	if req.Notes != nil {
		if !rec(observation.AttrNotes, *req.Notes) {
			return
		}
		wrote = true
	}
	if req.Icon != nil {
		if !rec(observation.AttrIcon, *req.Icon) {
			return
		}
		wrote = true
	}
	if !wrote {
		writeErr(w, http.StatusBadRequest, "no annotation fields provided")
		return
	}

	s.auditf(ctx, who, "host.annotate", "%s", req.StableID)
	s.reconcileNow(ctx)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "stable_id": req.StableID})
}

// reserveRequest is the body of POST /api/address/reserve.
type reserveRequest struct {
	IP       string `json:"ip"`
	Reserved bool   `json:"reserved"`
}

func (s *Server) handleReserve(w http.ResponseWriter, r *http.Request) {
	who, ok := s.requireOperator(w, r)
	if !ok {
		return
	}
	var req reserveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON")
		return
	}
	ip, version, err := netid.NormalizeIP(req.IP)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad ip")
		return
	}
	subjectType := observation.SubjectIPv4
	if version == 6 {
		subjectType = observation.SubjectIPv6
	}
	value := "released"
	if req.Reserved {
		value = "reserved"
	}
	if _, err := s.sink.Record(r.Context(), observation.SourceManual, subjectType, ip,
		observation.AttrReservation, value, manualConfidence); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auditf(r.Context(), who, "address.reserve", "%s reserved=%v", ip, req.Reserved)
	s.reconcileNow(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "ip": ip, "reserved": req.Reserved})
}

// reconcileNow refreshes the entity layer so the annotation is reflected at once.
func (s *Server) reconcileNow(ctx context.Context) {
	if s.reconcile == nil {
		return
	}
	if err := s.reconcile(ctx); err != nil {
		s.log.Warn("post-annotation reconcile failed", "err", err)
	}
}

// subjectFromStableID maps a host stable_id ("mac:.." / "ip:..") to the subject
// type and normalized identifier a manual observation should carry, so it routes
// back to that host in reconciliation.
func subjectFromStableID(stableID string) (observation.SubjectType, string, error) {
	v := stableIDValue(stableID)
	if v == "" {
		return "", "", errBadStableID
	}
	switch {
	case strings.HasPrefix(stableID, "mac:"):
		return observation.SubjectMAC, v, nil
	case strings.HasPrefix(stableID, "ip:"):
		_, version, err := netid.NormalizeIP(v)
		if err != nil {
			return "", "", errBadStableID
		}
		if version == 6 {
			return observation.SubjectIPv6, v, nil
		}
		return observation.SubjectIPv4, v, nil
	default:
		return "", "", errBadStableID
	}
}

func stableIDValue(stableID string) string {
	if i := strings.IndexByte(stableID, ':'); i >= 0 {
		return stableID[i+1:]
	}
	return ""
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

var errBadStableID = &apiError{"unrecognized host id"}

type apiError struct{ msg string }

func (e *apiError) Error() string { return e.msg }
