package api

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/tessera/tessera/internal/account"
	"github.com/tessera/tessera/internal/config"
	"github.com/tessera/tessera/internal/entity"
	"github.com/tessera/tessera/internal/secret"
	"github.com/tessera/tessera/internal/settings"
	"github.com/tessera/tessera/internal/store/sqlite"
)

type eventsResp struct {
	Events []entity.Event `json:"events"`
	Cursor int64          `json:"cursor"`
}

func TestEventsEndpoint(t *testing.T) {
	ctx := context.Background()
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "ev.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	if err := st.AppendEvents(ctx, []entity.Event{
		{At: t0, Kind: "new_device", StableID: "mac:aa", Message: "new a"},
		{At: t0.Add(time.Minute), Kind: "ip_changed", StableID: "mac:bb", Message: "b moved", Old: "10.0.0.2", New: "10.0.0.3"},
		{At: t0.Add(2 * time.Minute), Kind: "new_device", StableID: "mac:cc", Message: "new c"},
	}); err != nil {
		t.Fatal(err)
	}

	cipher, _ := secret.New(secret.GenerateKey())
	srv := New(Options{
		ListenAddr: "127.0.0.1:0", Token: testToken, Accounts: account.NewManager(st),
		Settings: settings.New(st, cipher), EffectiveConfig: config.Default(), Store: st,
	})
	ts := httptest.NewServer(srv.routes())
	t.Cleanup(ts.Close)

	// Default: newest-first, all kinds.
	all := getJSON[eventsResp](t, ts.URL+"/api/events")
	if len(all.Events) != 3 {
		t.Fatalf("got %d events, want 3", len(all.Events))
	}
	if all.Events[0].StableID != "mac:cc" {
		t.Errorf("newest-first: first = %q, want mac:cc", all.Events[0].StableID)
	}
	if all.Cursor != 3 {
		t.Errorf("cursor = %d, want 3", all.Cursor)
	}

	// Kind filter.
	nd := getJSON[eventsResp](t, ts.URL+"/api/events?kind=new_device")
	if len(nd.Events) != 2 {
		t.Errorf("kind=new_device → %d events, want 2", len(nd.Events))
	}

	// Incremental sync cursor: since=1 returns ids 2,3 ascending.
	sync := getJSON[eventsResp](t, ts.URL+"/api/events?since=1")
	if len(sync.Events) != 2 || sync.Events[0].ID != 2 || sync.Events[1].ID != 3 {
		t.Fatalf("since=1 → %+v, want ids [2,3] ascending", sync.Events)
	}
	if sync.Events[0].Old != "10.0.0.2" || sync.Events[0].New != "10.0.0.3" {
		t.Errorf("ip_changed old/new not carried: %+v", sync.Events[0])
	}
}
