package api

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// sqliteMagic is the 16-byte header every SQLite database file starts with.
const sqliteMagic = "SQLite format 3\x00"

// maxRestoreBytes caps an uploaded restore file (defensive; a homelab DB is well
// under this).
const maxRestoreBytes = 2 << 30 // 2 GiB

// handleAudit returns the recent audit trail (who changed what). Admin-only.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	entries, err := s.accounts.ListAudit(r.Context(), limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

// handleBackup streams a consistent snapshot of the database as a download.
func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	if s.dsn == "" {
		writeErr(w, http.StatusServiceUnavailable, "backup unavailable (no database path)")
		return
	}
	// A unique temp path so concurrent backups don't clobber each other.
	tf, err := os.CreateTemp(filepath.Dir(s.dsn), "tessera-backup-*.db")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	tmp := tf.Name()
	tf.Close()
	_ = os.Remove(tmp) // VACUUM INTO needs the destination not to exist
	defer os.Remove(tmp)
	if err := s.store.Backup(r.Context(), tmp); err != nil {
		writeErr(w, http.StatusInternalServerError, "backup failed: "+err.Error())
		return
	}
	f, err := os.Open(tmp)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer f.Close()
	name := "tessera-backup-" + time.Now().UTC().Format("2006-01-02-1504") + ".db"
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	_, _ = io.Copy(w, f)
}

// handleRestore stages an uploaded database to be swapped in on the next start,
// then triggers a restart. The file is sanity-checked for the SQLite header here;
// the app fully validates it (opens + checks the schema) before swapping.
func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	if s.dsn == "" {
		writeErr(w, http.StatusServiceUnavailable, "restore unavailable (no database path)")
		return
	}
	body := http.MaxBytesReader(w, r.Body, maxRestoreBytes)
	data, err := io.ReadAll(body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "upload too large or unreadable")
		return
	}
	if len(data) < len(sqliteMagic) || string(data[:len(sqliteMagic)]) != sqliteMagic {
		writeErr(w, http.StatusBadRequest, "not a SQLite database file")
		return
	}
	if err := os.WriteFile(s.dsn+".restore", data, 0o600); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.log.Warn("database restore staged — restarting to apply", "bytes", len(data))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "restarting": true})
	if s.onRestart != nil {
		go s.onRestart()
	}
}
