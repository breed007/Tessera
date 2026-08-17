package api

import (
	"net/http"

	"github.com/breed007/Tessera/internal/export"
)

// handleExport renders the current inventory in a requested interchange format
// (§M7). GET /api/export/{name} where name is one of export.Names().
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	spec, ok := export.Lookup(name)
	if !ok {
		writeErr(w, http.StatusNotFound, "unknown export format")
		return
	}
	snap, err := s.store.LoadEntities(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", spec.ContentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+spec.FileName+`"`)
	if _, err := export.Write(w, name, snap); err != nil {
		// Headers are already sent; just log.
		s.log.Error("export failed", "format", name, "err", err)
	}
}

// handleExportList lists available export formats (for the UI to render links).
func (s *Server) handleExportList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, export.Names())
}
