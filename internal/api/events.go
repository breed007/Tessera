package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/tessera/tessera/internal/entity"
)

// handleEvents serves the change history (the Activity feed + consumer sync).
//
//	GET /api/events?since=<id>&kind=<k1,k2>&limit=<n>
//
// With since>0 it returns events newer than that id in ascending order (an
// incremental-sync cursor); otherwise the newest first. The response carries a
// `cursor` = the highest id returned, to pass as the next `since`.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	since, _ := strconv.ParseInt(q.Get("since"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	var kinds []string
	if k := strings.TrimSpace(q.Get("kind")); k != "" {
		for _, part := range strings.Split(k, ",") {
			if p := strings.TrimSpace(part); p != "" {
				kinds = append(kinds, p)
			}
		}
	}
	ctx, cancel := contextWithTimeout(r, 10*time.Second)
	defer cancel()
	evs, err := s.store.ListEvents(ctx, entity.EventFilter{SinceID: since, Kinds: kinds, Limit: limit})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if evs == nil {
		evs = []entity.Event{}
	}
	// cursor = highest id in the page (0 when empty), for the next ?since=.
	var cursor int64
	for _, e := range evs {
		if e.ID > cursor {
			cursor = e.ID
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": evs, "cursor": cursor})
}
