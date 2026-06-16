package fingerbank

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tessera/tessera/internal/observation"
)

func TestSignatureCacheKeyExcludesMAC(t *testing.T) {
	a := Signature{DHCPFingerprint: "1,3,6,15", DHCPVendor: "android-dhcp", Hostname: "phoneA", MAC: "aa:aa:aa:aa:aa:aa"}
	b := Signature{DHCPFingerprint: "1,3,6,15", DHCPVendor: "android-dhcp", Hostname: "phoneB", MAC: "bb:bb:bb:bb:bb:bb"}
	if a.CacheKey() != b.CacheKey() {
		t.Error("same fingerprint/vendor must collapse regardless of MAC or hostname")
	}
	c := Signature{DHCPFingerprint: "1,3,6,15,33"}
	if a.CacheKey() == c.CacheKey() {
		t.Error("different fingerprint must produce a different key")
	}
}

func TestGovernorPacesAndBursts(t *testing.T) {
	g := newGovernor(3600, 1) // 1 token/sec, burst 1
	cur := time.Unix(0, 0)
	var slept []time.Duration
	g.now = func() time.Time { return cur }
	g.sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); cur = cur.Add(d); return nil }

	ctx := context.Background()
	_ = g.acquire(ctx) // burst token, immediate
	_ = g.acquire(ctx) // must wait ~1s for a refill
	if len(slept) != 1 || slept[0] != time.Second {
		t.Fatalf("pacing wrong: %v (want one 1s wait)", slept)
	}
}

func TestGovernorBackoff(t *testing.T) {
	g := newGovernor(360000, 100) // effectively unlimited tokens
	cur := time.Unix(0, 0)
	var slept []time.Duration
	g.now = func() time.Time { return cur }
	g.sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); cur = cur.Add(d); return nil }

	g.backoff(10 * time.Second)
	if err := g.acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(slept) == 0 || slept[0] < 9*time.Second {
		t.Errorf("expected ~10s backoff sleep, got %v", slept)
	}
}

func TestCacheTTL(t *testing.T) {
	c := newCache(time.Hour)
	t0 := time.Unix(1000, 0)
	c.put("k", Verdict{Found: true, DeviceClass: "X"}, t0)
	if v, ok := c.get("k", t0.Add(time.Minute)); !ok || v.DeviceClass != "X" {
		t.Error("should hit within TTL")
	}
	if _, ok := c.get("k", t0.Add(2*time.Hour)); ok {
		t.Error("should miss after TTL")
	}
}

// fakeDoer returns a canned HTTP response and captures the request.
type fakeDoer struct {
	status  int
	body    string
	lastReq *http.Request
}

func (f *fakeDoer) Do(r *http.Request) (*http.Response, error) {
	f.lastReq = r
	return &http.Response{StatusCode: f.status, Body: io.NopCloser(strings.NewReader(f.body))}, nil
}

func TestClientInterrogate(t *testing.T) {
	fd := &fakeDoer{status: 200, body: `{"device":{"name":"iPhone","parent_device":{"name":"Apple"}},"score":92,"version":"1"}`}
	c := &client{http: fd, endpoint: defaultEndpoint, key: "SECRET"}
	v, err := c.interrogate(context.Background(), Signature{DHCPFingerprint: "1,3,6", MAC: "aa:bb:cc:dd:ee:ff"})
	if err != nil {
		t.Fatal(err)
	}
	if !v.Found || v.DeviceClass != "Apple/iPhone" || v.Score != 92 {
		t.Errorf("verdict = %+v", v)
	}
	// Key goes in the query string; body carries the fingerprint and MAC.
	if got := fd.lastReq.URL.Query().Get("key"); got != "SECRET" {
		t.Errorf("key query = %q", got)
	}

	// 429 → rate limited; 404 → valid not-found.
	c.http = &fakeDoer{status: 429}
	if _, err := c.interrogate(context.Background(), Signature{}); err == nil {
		t.Error("429 should error (rate limited)")
	}
	c.http = &fakeDoer{status: 404}
	if v, err := c.interrogate(context.Background(), Signature{}); err != nil || v.Found {
		t.Errorf("404 should be not-found: %+v %v", v, err)
	}
}

func TestLocalDBOffline(t *testing.T) {
	// Build a fixture Fingerbank DB and classify against it — zero network.
	path := filepath.Join(t.TempDir(), "fb.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE combinations (dhcp_fingerprint TEXT, device_name TEXT, score INTEGER)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO combinations VALUES ('1,3,6,15,28,51,58,59', 'Android/Generic', 84)`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	enr, err := NewLocalDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer enr.Close()
	if enr.Mode() != "local_db" {
		t.Errorf("mode = %q", enr.Mode())
	}
	v, err := enr.Classify(context.Background(), Signature{DHCPFingerprint: "1,3,6,15,28,51,58,59"})
	if err != nil || !v.Found || v.DeviceClass != "Android/Generic" || v.Score != 84 {
		t.Errorf("local classify = %+v err=%v", v, err)
	}
	miss, _ := enr.Classify(context.Background(), Signature{DHCPFingerprint: "9,9,9"})
	if miss.Found {
		t.Error("unknown fingerprint should be not-found")
	}
}

// ── collector coalescing ─────────────────────────────────────────────────────

type fakeReader struct{ obs []observation.Observation }

func (r *fakeReader) Each(_ context.Context, _ int64, fn func(observation.Observation) error) error {
	for _, o := range r.obs {
		if err := fn(o); err != nil {
			return err
		}
	}
	return nil
}

type countingEnricher struct {
	calls int
	v     Verdict
}

func (e *countingEnricher) Classify(context.Context, Signature) (Verdict, error) {
	e.calls++
	return e.v, nil
}
func (e *countingEnricher) Mode() string { return "fake" }
func (e *countingEnricher) Close() error { return nil }

type fakeAppender struct{ got []observation.Observation }

func (a *fakeAppender) Append(_ context.Context, o observation.Observation) (int64, error) {
	a.got = append(a.got, o)
	return int64(len(a.got)), nil
}

func TestCollectorCoalescesBySignature(t *testing.T) {
	// Two MACs share the same DHCP fingerprint → one Classify, two emissions.
	reader := &fakeReader{obs: []observation.Observation{
		{SubjectType: observation.SubjectMAC, Subject: "aa:bb:cc:00:00:01", Attribute: observation.AttrDHCPFingerprint, Value: "1,3,6,15"},
		{SubjectType: observation.SubjectMAC, Subject: "aa:bb:cc:00:00:02", Attribute: observation.AttrDHCPFingerprint, Value: "1,3,6,15"},
	}}
	enr := &countingEnricher{v: Verdict{Found: true, DeviceClass: "Android", Score: 77}}
	app := &fakeAppender{}
	sink := observation.NewSink("fingerbank", app)

	c := NewCollector(enr, reader, time.Minute, nil)
	c.runOnce(context.Background(), sink)

	if enr.calls != 1 {
		t.Errorf("Classify called %d times, want 1 (coalesced)", enr.calls)
	}
	if len(app.got) != 2 {
		t.Fatalf("emitted %d observations, want 2 (one per MAC)", len(app.got))
	}
	for _, o := range app.got {
		if o.Source != observation.SourceFingerbank || o.Attribute != observation.AttrDeviceClass || o.Value != "Android" || o.Confidence != 77 {
			t.Errorf("bad emission: %+v", o)
		}
	}

	// A second run must not re-emit the unchanged signature.
	app.got = nil
	enr.calls = 0
	c.runOnce(context.Background(), sink)
	if enr.calls != 0 || len(app.got) != 0 {
		t.Errorf("second run should be a no-op: calls=%d emitted=%d", enr.calls, len(app.got))
	}
}
