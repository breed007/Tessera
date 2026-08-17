// Command tessera is the discovery-first IPAM daemon (see the build spec).
//
// Subcommands:
//
//	tessera run     [-config path]   run the daemon (default)
//	tessera migrate [-config path]   apply schema migrations and exit
//	tessera demo    [-config path]   seed synthetic observations, reconcile, print entities
//	tessera version                  print version and exit
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/breed007/Tessera/internal/app"
	"github.com/breed007/Tessera/internal/config"
)

// version (marketing) and buildNumber (YYYY.MM.DD.HH.mm build stamp) are set at
// build time via -ldflags. version is PINNED (1.0.1) and bumped by hand at real
// releases — NOT per commit; buildNumber increments every build.
var (
	version     = "1.0.1"
	buildNumber = "dev"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "tessera: "+err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	cmd := "run"
	if len(args) > 0 && !isFlag(args[0]) {
		cmd, args = args[0], args[1:]
	}

	switch cmd {
	case "version":
		fmt.Printf("tessera %s (build %s)\n", version, buildNumber)
		return nil
	case "run":
		return cmdRun(args)
	case "migrate":
		return cmdMigrate(args)
	case "demo":
		return cmdDemo(args)
	case "export":
		return cmdExport(args)
	case "setup":
		return cmdSetup(args)
	default:
		return fmt.Errorf("unknown command %q (run|setup|migrate|demo|export|version)", cmd)
	}
}

func isFlag(s string) bool { return len(s) > 0 && s[0] == '-' }

// newLogger builds the structured logger. Secrets are never passed to it; the
// config secret fields are not part of any logged value.
func newLogger(level slog.Level) *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

func loadConfig(args []string, name string) (config.Config, *slog.Logger, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	path := fs.String("config", "configs/tessera.example.yaml", "path to config file")
	debug := fs.Bool("debug", false, "verbose logging")
	if err := fs.Parse(args); err != nil {
		return config.Config{}, nil, err
	}
	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := newLogger(level)
	cfg, err := config.Load(*path)
	if err != nil {
		return config.Config{}, log, err
	}
	return cfg, log, nil
}

// cmdRun starts the daemon and blocks until SIGINT/SIGTERM, then shuts down
// cleanly (§M0 graceful shutdown).
func cmdRun(args []string) error {
	cfg, log, err := loadConfig(args, "run")
	if err != nil {
		return err
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// A manual cancel layer so the API's "restart to apply settings" can trigger a
	// clean exit (systemd Restart=always brings the process back with new settings).
	ctx, cancel := context.WithCancel(sigCtx)
	defer cancel()

	app.Version, app.Build = version, buildNumber
	a, err := app.New(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer a.Close()
	a.SetRestart(cancel)

	if err := a.Run(ctx); err != nil {
		return err
	}
	log.Info("tessera stopped cleanly")
	return nil
}

// cmdMigrate applies migrations and exits.
func cmdMigrate(args []string) error {
	cfg, log, err := loadConfig(args, "migrate")
	if err != nil {
		return err
	}
	ctx := context.Background()
	a, err := app.New(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer a.Close()
	log.Info("migrations applied")
	return nil
}
