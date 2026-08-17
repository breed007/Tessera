package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/breed007/Tessera/internal/app"
	"github.com/breed007/Tessera/internal/observation"
	"github.com/breed007/Tessera/internal/reconcile"
)

// cmdDemo seeds a handful of synthetic observations through the standard write
// path (observation.Sink — exactly what a real collector uses), reconciles the
// log into entities, and prints the result. It demonstrates the M1 architecture
// end-to-end without any live network collector.
func cmdDemo(args []string) error {
	cfg, log, err := loadConfig(args, "demo")
	if err != nil {
		return err
	}
	ctx := context.Background()
	a, err := app.New(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer a.Close()

	// t0 anchors the synthetic timeline so the demo is deterministic.
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Two "collectors" writing into the one log, in the one shape.
	arp := observation.NewSink("demo-passive-arp", a.Store())
	probe := observation.NewSink("demo-active-probe", a.Store())

	seed := []func() (int64, error){
		// A normal device seen via ARP: MAC↔IP binding + vendor + hostname.
		func() (int64, error) {
			return arp.Record(ctx, observation.SourcePassiveARP, observation.SubjectMAC,
				"b8:27:eb:11:22:33", observation.AttrIPBinding, "10.0.0.20", 95,
				observation.At(t0))
		},
		func() (int64, error) {
			return arp.Record(ctx, observation.SourcePassiveARP, observation.SubjectMAC,
				"b8:27:eb:11:22:33", observation.AttrOUIVendor, "Raspberry Pi Foundation", 90,
				observation.At(t0))
		},
		func() (int64, error) {
			return arp.Record(ctx, observation.SourcePassiveDHCP, observation.SubjectMAC,
				"b8:27:eb:11:22:33", observation.AttrHostname, "pihole", 80,
				observation.At(t0.Add(time.Second)))
		},
		// A randomized-MAC device (locally-administered bit set) — §6.
		func() (int64, error) {
			return arp.Record(ctx, observation.SourcePassiveARP, observation.SubjectMAC,
				"aa:bb:cc:dd:ee:ff", observation.AttrIPBinding, "10.0.0.55", 95,
				observation.At(t0.Add(2*time.Second)))
		},
		func() (int64, error) {
			return arp.Record(ctx, observation.SourcePassiveDHCP, observation.SubjectMAC,
				"aa:bb:cc:dd:ee:ff", observation.AttrHostname, "iPhone", 70,
				observation.At(t0.Add(3*time.Second)))
		},
		// An IP seen alive by the active prober with no MAC yet → provisional host.
		func() (int64, error) {
			return probe.Record(ctx, observation.SourceActiveICMP, observation.SubjectIPv4,
				"10.0.0.99", observation.AttrLiveness, "up", 85,
				observation.At(t0.Add(4*time.Second)))
		},
		// Two sources disagree on the Pi's device_class → a recorded conflict.
		// UniFi (strong tier) says NAS; Fingerbank (inferential) says SBC. The
		// higher-confidence/higher-tier value stays current; the disagreement is
		// surfaced, not hidden (§3.3).
		func() (int64, error) {
			return arp.Record(ctx, observation.SourceUniFi, observation.SubjectMAC,
				"b8:27:eb:11:22:33", observation.AttrDeviceClass, "NAS", 70,
				observation.At(t0.Add(5*time.Second)))
		},
		func() (int64, error) {
			return arp.Record(ctx, observation.SourceFingerbank, observation.SubjectMAC,
				"b8:27:eb:11:22:33", observation.AttrDeviceClass, "Single-Board Computer", 88,
				observation.At(t0.Add(6*time.Second)))
		},
		// UniFi-sourced facts (§4.3): a configured network seeds a subnet, and a
		// switch port↔MAC mapping seeds topology. The addresses above fall inside
		// this subnet, so reconciliation links them by membership.
		func() (int64, error) {
			hint := observation.SubnetHintValue{CIDR: "10.0.0.0/24", Name: "LAN", Gateway: "10.0.0.1"}
			return arp.Record(ctx, observation.SourceUniFi, observation.SubjectIPv4,
				"10.0.0.0", observation.AttrSubnetHint, hint.MarshalValue(), 95,
				observation.At(t0.Add(7*time.Second)))
		},
		func() (int64, error) {
			return arp.Record(ctx, observation.SourceUniFi, observation.SubjectMAC,
				"b8:27:eb:11:22:33", observation.AttrSwitchPort, "f0:9f:c2:aa:bb:cc/5", 95,
				observation.At(t0.Add(8*time.Second)))
		},
	}

	for _, fn := range seed {
		if _, err := fn(); err != nil {
			return fmt.Errorf("demo seed: %w", err)
		}
	}

	// Reconcile with a clock anchored just after the synthetic timeline so the
	// demo's addresses are "active" and confidences aren't decayed to zero.
	clock := t0.Add(time.Minute)
	recon := reconcile.New(a.Store(), log, reconcile.Params{
		Now: func() time.Time { return clock },
	})
	if _, err := recon.Rebuild(ctx); err != nil {
		return err
	}

	snap, err := a.Store().LoadEntities(ctx)
	if err != nil {
		return err
	}
	count, _ := a.Store().CountObservations(ctx)
	fmt.Printf("\n── Tessera demo: %d observations folded into entities ──\n\n", count)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(snap)
}
