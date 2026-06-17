package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"

	"github.com/tessera/tessera/internal/collector"
	"github.com/tessera/tessera/internal/collector/active"
)

// handleVersion reports the marketing version + build stamp for the UI footer.
// Public (shown on the login screen too).
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"version": s.version, "build": s.build})
}

// handleStatus reports collector connection health (UniFi, Fingerbank). Read-only,
// so any authenticated user may see it.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	var out []collector.Status
	if s.statuses != nil {
		out = s.statuses()
	}
	if out == nil {
		out = []collector.Status{}
	}
	writeJSON(w, http.StatusOK, out)
}

// On-demand rescan: actively probe a single host's addresses or a whole subnet
// right now, then reconcile. A host has few addresses and probes in seconds, so
// it runs synchronously; a subnet can be hundreds of targets, so it runs in the
// background and the UI refreshes on its own. Both are admin-only (they put
// traffic on the network) and gentle (the prober's rate limiter + bounded
// concurrency + SPAN-safe egress apply).

type rescanHostRequest struct {
	StableID string `json:"stable_id"`
}

type rescanSubnetRequest struct {
	SubnetID int64 `json:"subnet_id"`
}

func (s *Server) handleRescanHost(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	if s.rescan == nil {
		writeErr(w, http.StatusServiceUnavailable, "rescan unavailable")
		return
	}
	var req rescanHostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON")
		return
	}
	ctx := r.Context()
	snap, err := s.store.LoadEntities(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	host, ok := findHost(snap, req.StableID)
	if !ok {
		writeErr(w, http.StatusNotFound, "host not found")
		return
	}
	var targets []netip.Addr
	for _, a := range snap.Addresses {
		if a.HostID != nil && *a.HostID == host.ID {
			if ip, err := netip.ParseAddr(a.IP); err == nil {
				targets = append(targets, ip)
			}
		}
	}
	if len(targets) == 0 {
		writeErr(w, http.StatusBadRequest, "host has no probeable addresses")
		return
	}
	// Synchronous: a host is a handful of addresses, done in seconds.
	if err := s.rescan(ctx, targets); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "probed": len(targets)})
}

func (s *Server) handleRescanSubnet(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	if s.rescan == nil {
		writeErr(w, http.StatusServiceUnavailable, "rescan unavailable")
		return
	}
	var req rescanSubnetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON")
		return
	}
	snap, err := s.store.LoadEntities(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	cidr := ""
	for _, sn := range snap.Subnets {
		if sn.ID == req.SubnetID {
			cidr = sn.CIDR
			break
		}
	}
	if cidr == "" {
		writeErr(w, http.StatusNotFound, "subnet not found")
		return
	}
	targets, skipped, err := active.EnumerateTargets([]string{cidr})
	if err != nil || len(targets) == 0 {
		writeErr(w, http.StatusBadRequest, "subnet not probeable: "+cidr)
		return
	}
	// Asynchronous: a subnet can be hundreds of targets and take minutes. Detach
	// from the request context so it isn't cancelled when we return 202; the UI
	// refreshes once the background reconcile lands.
	bg := context.WithoutCancel(r.Context())
	go func() {
		if err := s.rescan(bg, targets); err != nil {
			s.log.Warn("subnet rescan failed", "cidr", cidr, "err", err)
		}
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok": true, "started": true, "cidr": cidr, "targets": len(targets), "skipped": skipped,
	})
}
