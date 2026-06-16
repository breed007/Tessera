// Package web serves the embedded minimal UI (§M6). The assets are baked into
// the binary so Tessera stays a single self-contained artifact.
package web

import (
	"embed"
	"io/fs"
	"net/http"
	"sort"
	"strings"
)

//go:embed assets
var assets embed.FS

// Handler serves the static UI assets (index.html at "/"; icons under
// /icons/lib/...).
func Handler() http.Handler {
	sub, err := fs.Sub(assets, "assets")
	if err != nil {
		panic(err) // embedded FS is known-good at build time
	}
	return http.FileServer(http.FS(sub))
}

// LibIcons lists the bundled device icon ids (§M12), without the .svg suffix.
func LibIcons() []string {
	entries, err := fs.ReadDir(assets, "assets/icons/lib")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if name := e.Name(); strings.HasSuffix(name, ".svg") {
			out = append(out, strings.TrimSuffix(name, ".svg"))
		}
	}
	sort.Strings(out)
	return out
}
