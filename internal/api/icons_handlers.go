package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/breed007/Tessera/internal/icons"
	"github.com/breed007/Tessera/internal/web"
)

var iconIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,40}$`)

// svgActiveContentRe catches the obvious script vectors in an uploaded SVG:
// <script>, <foreignObject> (can host HTML/JS), javascript: URLs, and inline
// on* event handlers. This is defense-in-depth and immediate operator feedback,
// NOT the primary control — SVG can smuggle script past a regex (entities,
// namespaces), so the real protection is the sandbox CSP on the served file.
var svgActiveContentRe = regexp.MustCompile(`(?i)<\s*script\b|<\s*foreignobject\b|javascript:|\son\w+\s*=`)

// iconDir is where custom (uploaded) icons live.
func (s *Server) iconDir() string { return filepath.Join(s.dataDir, "icons") }

// IconInfo describes one library icon.
type IconInfo struct {
	ID     string `json:"id"`
	Source string `json:"source"` // bundled | custom
	URL    string `json:"url"`
}

// effectiveIcon returns the icon id + URL for a host: the operator's manual
// choice if set, otherwise the auto-assignment, resolved to a custom or bundled
// asset URL.
func (s *Server) effectiveIcon(iconID, vendor, os, deviceClass, model string) (string, string) {
	id := iconID
	if id == "" {
		id = icons.Auto(vendor, os, deviceClass, model)
	}
	return id, s.iconURL(id)
}

func (s *Server) iconURL(id string) string {
	if id == "" {
		return ""
	}
	if fileExists(filepath.Join(s.iconDir(), id+".svg")) {
		return "/icons/custom/" + id + ".svg"
	}
	return "/icons/lib/" + id + ".svg"
}

func (s *Server) handleListIcons(w http.ResponseWriter, r *http.Request) {
	seen := map[string]bool{}
	var out []IconInfo
	for _, id := range web.LibIcons() {
		seen[id] = true
		out = append(out, IconInfo{ID: id, Source: "bundled", URL: "/icons/lib/" + id + ".svg"})
	}
	if entries, err := os.ReadDir(s.iconDir()); err == nil {
		for _, e := range entries {
			id := strings.TrimSuffix(e.Name(), ".svg")
			if strings.HasSuffix(e.Name(), ".svg") && !seen[id] {
				out = append(out, IconInfo{ID: id, Source: "custom", URL: "/icons/custom/" + id + ".svg"})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	writeJSON(w, http.StatusOK, out)
}

// handleUploadIcon stores a custom SVG icon (admin). Body: {id, svg}.
func (s *Server) handleUploadIcon(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireOperator(w, r); !ok {
		return
	}
	var req struct{ ID, SVG string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON")
		return
	}
	req.ID = strings.ToLower(strings.TrimSpace(req.ID))
	if !iconIDRe.MatchString(req.ID) {
		writeErr(w, http.StatusBadRequest, "id must be lowercase letters/digits/-/_ (max 41 chars)")
		return
	}
	if !strings.Contains(req.SVG, "<svg") || len(req.SVG) > 256*1024 {
		writeErr(w, http.StatusBadRequest, "expected an SVG under 256 KB")
		return
	}
	if svgActiveContentRe.MatchString(req.SVG) {
		writeErr(w, http.StatusBadRequest, "the SVG contains scripts or event handlers — icons must be static shapes only")
		return
	}
	if err := os.MkdirAll(s.iconDir(), 0o750); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := os.WriteFile(filepath.Join(s.iconDir(), req.ID+".svg"), []byte(req.SVG), 0o640); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "id": req.ID})
}

// handleDeleteIcon removes a custom icon (admin). Bundled icons can't be deleted.
func (s *Server) handleDeleteIcon(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireOperator(w, r); !ok {
		return
	}
	id := r.PathValue("id")
	if !iconIDRe.MatchString(id) {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	if err := os.Remove(filepath.Join(s.iconDir(), id+".svg")); err != nil {
		writeErr(w, http.StatusNotFound, "no such custom icon")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleCustomIcon serves an uploaded icon from the data dir.
func (s *Server) handleCustomIcon(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSuffix(r.PathValue("id"), ".svg")
	if !iconIDRe.MatchString(id) { // also blocks path traversal
		http.NotFound(w, r)
		return
	}
	path := filepath.Join(s.iconDir(), id+".svg")
	if !fileExists(path) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	// A custom icon is operator-uploaded content served as an active format
	// (SVG can carry <script>). The sandbox CSP makes the browser treat it as an
	// opaque origin with scripts/plugins disabled, so even a script-laden SVG
	// can't execute or reach Tessera's origin on direct navigation; nosniff stops
	// content-type confusion. It still renders fine as an inline image / CSS mask.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeFile(w, r, path)
}
