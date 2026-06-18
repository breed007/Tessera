package alert

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/tessera/tessera/internal/entity"
)

type fakeStore struct {
	snap entity.Snapshot
	kv   map[string]string
}

func (f *fakeStore) LoadEntities(context.Context) (entity.Snapshot, error) { return f.snap, nil }
func (f *fakeStore) SettingGet(_ context.Context, k string) (string, bool, error) {
	v, ok := f.kv[k]
	return v, ok, nil
}
func (f *fakeStore) SettingSet(_ context.Context, k, v string, _ bool) error {
	f.kv[k] = v
	return nil
}

func id(n int64) *int64 { return &n }

func TestEngineBaselineThenNewDevice(t *testing.T) {
	var mu sync.Mutex
	var got []Event
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var ev Event
		_ = json.Unmarshal(b, &ev)
		mu.Lock()
		got = append(got, ev)
		mu.Unlock()
	}))
	defer srv.Close()

	fs := &fakeStore{kv: map[string]string{}, snap: entity.Snapshot{
		Hosts:     []entity.Host{{ID: 1, StableID: "mac:aa", DisplayName: "known", IsExpected: true}},
		Addresses: []entity.Address{{IP: "10.0.0.1", HostID: id(1), State: entity.StateActive}},
	}}
	cfg := Config{Enabled: true, Kind: "webhook", URL: srv.URL, NewDevice: true, Offline: true, Online: true, IPChanged: true, Conflict: true}
	e := New(fs, cfg, nil)

	// First run seeds the baseline silently.
	if err := e.Process(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	n := len(got)
	mu.Unlock()
	if n != 0 {
		t.Fatalf("first run dispatched %d alerts, want 0 (silent baseline)", n)
	}

	// A new, unexpected device appears → exactly one new_device alert.
	fs.snap.Hosts = append(fs.snap.Hosts, entity.Host{ID: 2, StableID: "mac:bb", DisplayName: "newbie", DeviceClass: "computer"})
	fs.snap.Addresses = append(fs.snap.Addresses, entity.Address{IP: "10.0.0.2", HostID: id(2), State: entity.StateActive})
	if err := e.Process(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0].Type != TypeNewDevice || got[0].Subject != "mac:bb" {
		t.Fatalf("after new device, alerts = %+v, want one new_device for mac:bb", got)
	}
}

func TestEngineRiskyService(t *testing.T) {
	var mu sync.Mutex
	var got []Event
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var ev Event
		_ = json.Unmarshal(b, &ev)
		mu.Lock()
		got = append(got, ev)
		mu.Unlock()
	}))
	defer srv.Close()

	fs := &fakeStore{kv: map[string]string{}, snap: entity.Snapshot{
		Hosts:     []entity.Host{{ID: 1, StableID: "mac:aa", DisplayName: "nas"}},
		Addresses: []entity.Address{{IP: "10.0.0.5", HostID: id(1), State: entity.StateActive}},
		Services:  []entity.Service{{HostID: id(1), Proto: "tcp", Port: 443}}, // not risky
	}}
	cfg := Config{Enabled: true, Kind: "webhook", URL: srv.URL, RiskyService: true}
	e := New(fs, cfg, nil)
	if err := e.Process(context.Background()); err != nil { // first run = silent baseline
		t.Fatal(err)
	}
	mu.Lock()
	n := len(got)
	mu.Unlock()
	if n != 0 {
		t.Fatalf("baseline dispatched %d, want 0", n)
	}

	// Telnet appears on the host → one risky_service alert.
	fs.snap.Services = append(fs.snap.Services, entity.Service{HostID: id(1), Proto: "tcp", Port: 23})
	if err := e.Process(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0].Type != TypeRiskyService || got[0].Subject != "mac:aa" {
		t.Fatalf("after telnet appears, alerts = %+v, want one risky_service for mac:aa", got)
	}
}

func TestEngineDisabledNoop(t *testing.T) {
	fs := &fakeStore{kv: map[string]string{}}
	e := New(fs, Config{Enabled: false}, nil)
	if err := e.Process(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := fs.kv[stateKey]; ok {
		t.Error("disabled engine should not touch state")
	}
}
