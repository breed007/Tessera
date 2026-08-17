package api

import (
	"net/http"
	"os"
	"time"

	"github.com/breed007/Tessera/internal/collector"
)

// SystemInfo is the operator's at-a-glance health snapshot: collectors, data
// volume, backpressure, and build — everything needed to answer "is Tessera
// actually working?" without digging through logs.
type SystemInfo struct {
	Version           string             `json:"version"`
	Build             string             `json:"build"`
	UptimeSeconds     int64              `json:"uptime_seconds"`
	Collectors        []collector.Status `json:"collectors"`
	ObservationsTotal int64              `json:"observations_total"`
	EventsTotal       int                `json:"events_total"`
	Dropped           int64              `json:"dropped"` // observations dropped under backpressure (SPAN overload)
	DBSizeBytes       int64              `json:"db_size_bytes"`
	Hosts             int                `json:"hosts"`
	Addresses         int                `json:"addresses"`
	Services          int                `json:"services"`
	Subnets           int                `json:"subnets"`
	Conflicts         int                `json:"conflicts"`
}

func (s *Server) handleSystem(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	ctx, cancel := contextWithTimeout(r, 10*time.Second)
	defer cancel()

	info := SystemInfo{
		Version:       s.version,
		Build:         s.build,
		UptimeSeconds: int64(time.Since(s.startedAt).Seconds()),
	}
	if s.statuses != nil {
		info.Collectors = s.statuses()
	}
	if info.Collectors == nil {
		info.Collectors = []collector.Status{}
	}
	if s.dropped != nil {
		info.Dropped = s.dropped()
	}
	info.ObservationsTotal, _ = s.store.CountObservations(ctx)
	info.DBSizeBytes = dbSize(s.dsn)

	if snap, err := s.store.LoadEntities(ctx); err == nil {
		info.Hosts = len(snap.Hosts)
		info.Addresses = len(snap.Addresses)
		info.Services = len(snap.Services)
		info.Subnets = len(snap.Subnets)
		info.Conflicts = len(snap.Conflicts)
	}
	if n, err := s.store.CountEvents(ctx); err == nil {
		info.EventsTotal = int(n)
	}

	writeJSON(w, http.StatusOK, info)
}

// dbSize sums the SQLite database file and its WAL/SHM sidecars.
func dbSize(dsn string) int64 {
	if dsn == "" {
		return 0
	}
	var total int64
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if fi, err := os.Stat(dsn + suffix); err == nil {
			total += fi.Size()
		}
	}
	return total
}
