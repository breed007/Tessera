package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/breed007/Tessera/internal/config"
	"github.com/breed007/Tessera/internal/export"
	"github.com/breed007/Tessera/internal/store/sqlite"
)

// cmdExport renders the current reconciled inventory to an interchange format
// (§M7), to stdout or a file. It reads the persisted entity layer — run the
// daemon at least once so there's something to export.
func cmdExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	path := fs.String("config", "configs/tessera.example.yaml", "path to config file")
	format := fs.String("format", "inventory.json", "export format: "+strings.Join(export.Names(), ", "))
	out := fs.String("out", "", "output file (default: stdout)")
	list := fs.Bool("list", false, "list available export formats and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *list {
		for _, n := range export.Names() {
			fmt.Println(n)
		}
		return nil
	}

	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	if cfg.Storage.Driver != "sqlite" {
		return fmt.Errorf("export: only sqlite storage is supported")
	}
	st, err := sqlite.Open(cfg.Storage.DSN)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	snap, err := st.LoadEntities(ctx)
	if err != nil {
		return err
	}

	w := os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	if _, err := export.Write(w, *format, snap); err != nil {
		return err
	}
	if *out != "" {
		fmt.Fprintf(os.Stderr, "exported %s → %s\n", *format, *out)
	}
	return nil
}
