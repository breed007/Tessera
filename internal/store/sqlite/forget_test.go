package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/tessera/tessera/internal/entity"
	"github.com/tessera/tessera/internal/observation"
	"github.com/tessera/tessera/internal/store"
)

func TestForgetSubjects(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "f.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	const mac, ip, other = "aa:bb:cc:00:00:01", "10.0.0.5", "aa:bb:cc:00:00:99"
	add := func(subj string, sty observation.SubjectType, src observation.Source, off time.Duration) {
		if _, err := st.Append(ctx, observation.Observation{
			ObservedAt: t0.Add(off), Source: src, CollectorID: "x",
			SubjectType: sty, Subject: subj, Attribute: observation.AttrIPBinding, Value: "v", Confidence: 90,
		}); err != nil {
			t.Fatal(err)
		}
	}
	add(mac, observation.SubjectMAC, observation.SourceUniFi, 0)
	add(ip, observation.SubjectIPv4, observation.SourceActiveTCP, time.Minute)
	add(other, observation.SubjectMAC, observation.SourceUniFi, 2*time.Minute) // a different device — must survive

	// Workflow state tied to the host.
	if err := st.SetSecuritySuppression(ctx, entity.SecuritySuppression{StableID: "mac:" + mac, Proto: "tcp", Port: 23}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetResolution(ctx, entity.ConflictResolution{Subject: "mac:" + mac, Attribute: "device_class", ResolvedAt: t0}); err != nil {
		t.Fatal(err)
	}
	// Change-history events for this host (and one for another host that must survive).
	if err := st.AppendEvents(ctx, []entity.Event{
		{At: t0, Kind: "new_device", StableID: "mac:" + mac, Message: "new"},
		{At: t0, Kind: "device_offline", StableID: "mac:" + mac, Message: "offline"},
		{At: t0, Kind: "new_device", StableID: "mac:" + other, Message: "other"},
	}); err != nil {
		t.Fatal(err)
	}

	removed, err := st.ForgetSubjects(ctx, "mac:"+mac, []string{mac, ip})
	if err != nil {
		t.Fatal(err)
	}
	if removed != 2 {
		t.Fatalf("removed = %d, want 2 (mac + ip observations)", removed)
	}
	// The forgotten subjects' observations are gone; the other device's remain.
	if obs, _ := st.ForSubjects(ctx, []string{mac, ip}); len(obs) != 0 {
		t.Errorf("forgotten observations remain: %+v", obs)
	}
	if obs, _ := st.ForSubjects(ctx, []string{other}); len(obs) != 1 {
		t.Errorf("other device's observation should survive, got %d", len(obs))
	}
	// Workflow state cleared.
	if sp, _ := st.ListSecuritySuppressions(ctx); len(sp) != 0 {
		t.Errorf("suppression should be cleared: %+v", sp)
	}
	if rs, _ := st.ListResolutions(ctx); len(rs) != 0 {
		t.Errorf("resolution should be cleared: %+v", rs)
	}
	// The forgotten host's change events are gone; the other host's survives.
	evs, _ := st.ListEvents(ctx, entity.EventFilter{})
	if len(evs) != 1 || evs[0].StableID != "mac:"+other {
		t.Errorf("after forget, events = %+v, want only the other host's", evs)
	}
}

func TestEventsPruneAndCount(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "ev.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	batch := make([]entity.Event, 0, 50)
	for i := 0; i < 50; i++ {
		batch = append(batch, entity.Event{At: t0.Add(time.Duration(i) * time.Second), Kind: "new_device", StableID: "mac:x", Message: "e"})
	}
	if err := st.AppendEvents(ctx, batch); err != nil {
		t.Fatal(err)
	}
	if n, _ := st.CountEvents(ctx); n != 50 {
		t.Fatalf("count = %d, want 50", n)
	}
	// Keep the newest 10.
	removed, err := st.PruneEvents(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 40 {
		t.Errorf("pruned %d, want 40", removed)
	}
	if n, _ := st.CountEvents(ctx); n != 10 {
		t.Errorf("after prune count = %d, want 10", n)
	}
	// The survivors are the newest ids (41..50).
	kept, _ := st.ListEvents(ctx, entity.EventFilter{Limit: 100})
	if len(kept) != 10 || kept[0].ID != 50 {
		t.Errorf("kept newest? first id = %d, want 50; kept %d", kept[0].ID, len(kept))
	}
	// keep<=0 is a no-op.
	if removed, _ := st.PruneEvents(ctx, 0); removed != 0 {
		t.Errorf("prune(0) removed %d, want 0", removed)
	}
}

func TestDeleteObservations(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "del.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	add := func(sty observation.SubjectType, subj string, a observation.Attribute, v string) int64 {
		id, err := st.Append(ctx, observation.Observation{
			ObservedAt: t0, Source: observation.SourceActiveTCP, CollectorID: "x",
			SubjectType: sty, Subject: subj, Attribute: a, Value: v, Confidence: 80,
		})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	id := add(observation.SubjectIPv4, "10.0.0.5", observation.AttrOpenPort, "tcp/23")
	add(observation.SubjectIPv4, "10.0.0.5", observation.AttrOpenPort, "tcp/443")
	add(observation.SubjectIPv4, "10.0.0.5", observation.AttrServiceBanner, "tcp/23|telnetd")
	add(observation.SubjectMAC, "aa:bb:cc:00:00:01", observation.AttrIPBinding, "10.0.0.5")

	// Empty filter is refused.
	if _, err := st.DeleteObservations(ctx, store.ObsDeleteFilter{}); err == nil {
		t.Fatal("empty filter should be refused")
	}
	// Delete one observation by id.
	if n, err := st.DeleteObservation(ctx, id); err != nil || n != 1 {
		t.Fatalf("DeleteObservation = %d,%v want 1,nil", n, err)
	}
	// Delete a service: the tcp/443 open_port + (via prefix) its banners.
	add(observation.SubjectIPv4, "10.0.0.5", observation.AttrServiceBanner, "tcp/443|nginx")
	if n, err := st.DeleteObservations(ctx, store.ObsDeleteFilter{Subject: "10.0.0.5", Attribute: string(observation.AttrServiceBanner), ValuePrefix: "tcp/443|"}); err != nil || n != 1 {
		t.Fatalf("banner prefix delete = %d,%v want 1,nil", n, err)
	}
	// Delete the binding by value (all MACs pointing at the IP).
	if n, err := st.DeleteObservations(ctx, store.ObsDeleteFilter{Attribute: string(observation.AttrIPBinding), Value: "10.0.0.5"}); err != nil || n != 1 {
		t.Fatalf("binding value delete = %d,%v want 1,nil", n, err)
	}
}

func TestBackup(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "src.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Append(ctx, observation.Observation{
		ObservedAt: time.Now(), Source: observation.SourceUniFi, CollectorID: "x",
		SubjectType: observation.SubjectMAC, Subject: "aa:bb:cc:00:00:01", Attribute: observation.AttrIPBinding, Value: "10.0.0.5", Confidence: 90,
	}); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "backup.db")
	if err := st.Backup(ctx, dest); err != nil {
		t.Fatalf("backup: %v", err)
	}
	// The backup opens as a valid Tessera DB with the same data.
	bk, err := Open(dest)
	if err != nil {
		t.Fatalf("open backup: %v", err)
	}
	defer bk.Close()
	if n, err := bk.CountObservations(ctx); err != nil || n != 1 {
		t.Fatalf("backup observations = %d,%v want 1,nil", n, err)
	}
}

func TestAvailability(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "av.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	if err := st.AppendAvailability(ctx, []entity.AvailabilityEvent{
		{StableID: "mac:aa", Online: true, At: t0},
		{StableID: "mac:aa", Online: false, At: t0.Add(time.Hour)},
		{StableID: "mac:bb", Online: true, At: t0},
	}); err != nil {
		t.Fatal(err)
	}
	latest, err := st.LatestAvailability(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if latest["mac:aa"] != false || latest["mac:bb"] != true {
		t.Fatalf("latest = %+v, want aa=false bb=true", latest)
	}
	evs, err := st.AvailabilityForHost(ctx, "mac:aa")
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 || !evs[0].Online || evs[1].Online {
		t.Fatalf("aa events = %+v, want [online, offline] oldest-first", evs)
	}
	// Forget clears availability history.
	if _, err := st.ForgetSubjects(ctx, "mac:aa", []string{"aa"}); err != nil {
		t.Fatal(err)
	}
	if evs, _ := st.AvailabilityForHost(ctx, "mac:aa"); len(evs) != 0 {
		t.Errorf("availability should be cleared after forget: %+v", evs)
	}
}

func TestLastSeenBySubject(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "ls.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	rec := func(subj string, src observation.Source, at time.Time) {
		if _, err := st.Append(ctx, observation.Observation{
			ObservedAt: at, Source: src, CollectorID: "x", SubjectType: observation.SubjectMAC,
			Subject: subj, Attribute: observation.AttrIPBinding, Value: "v", Confidence: 90,
		}); err != nil {
			t.Fatal(err)
		}
	}
	rec("aa", observation.SourceUniFi, t0)
	rec("aa", observation.SourceUniFi, t0.Add(48*time.Hour)) // newest network sighting
	rec("aa", observation.SourceManual, t0.Add(100*time.Hour)) // manual edit must be excluded
	rec("bb", observation.SourceManual, t0)                    // manual-only → absent from map

	m, err := st.LastSeenBySubject(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := m["aa"]; !got.Equal(t0.Add(48 * time.Hour)) {
		t.Errorf("last-seen aa = %v, want %v (manual excluded)", got, t0.Add(48*time.Hour))
	}
	if _, ok := m["bb"]; ok {
		t.Errorf("manual-only subject bb should not appear in last-seen map")
	}
}
