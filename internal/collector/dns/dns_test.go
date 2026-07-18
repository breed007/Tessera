package dns

import (
	"context"
	"testing"

	"github.com/tessera/tessera/internal/observation"
)

func TestParseHostsLine(t *testing.T) {
	cases := []struct {
		name     string
		line     string
		wantOK   bool
		wantIP   string
		wantName string
	}{
		{"simple", "192.168.1.10 nas", true, "192.168.1.10", "nas"},
		{"fqdn+alias", "10.0.0.5   printer.lan printer", true, "10.0.0.5", "printer.lan"},
		{"tabs", "10.0.0.6\tswitch", true, "10.0.0.6", "switch"},
		{"trailing comment", "10.0.0.7 apbeta # top of rack", true, "10.0.0.7", "apbeta"},
		{"trailing dot stripped", "10.0.0.8 host.lan.", true, "10.0.0.8", "host.lan"},
		{"ipv6", "fe80::1 router6", true, "fe80::1", "router6"},
		{"whole-line comment", "# 10.0.0.8 ignored", false, "", ""},
		{"blank", "   ", false, "", ""},
		{"no name", "10.0.0.9", false, "", ""},
		{"not an ip", "notanip host", false, "", ""},
		{"localhost skipped", "127.0.0.1 localhost", false, "", ""},
		{"localhost any-case skipped", "::1 LocalHost", false, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, ok := parseHostsLine(c.line)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v (line %q)", ok, c.wantOK, c.line)
			}
			if !ok {
				return
			}
			if r.IP != c.wantIP || r.Name != c.wantName {
				t.Fatalf("got {%q %q}, want {%q %q}", r.IP, r.Name, c.wantIP, c.wantName)
			}
		})
	}
}

func TestParseUnboundLine(t *testing.T) {
	cases := []struct {
		name     string
		line     string
		wantOK   bool
		wantIP   string
		wantName string
	}{
		{"a record", `local-data: "nas.lan. IN A 10.0.0.10"`, true, "10.0.0.10", "nas.lan"},
		{"a no-class", `  local-data: "printer.lan. A 10.0.0.11"`, true, "10.0.0.11", "printer.lan"},
		{"aaaa", `local-data: "router6.lan. AAAA fd00::5"`, true, "fd00::5", "router6.lan"},
		{"with ttl", `local-data: "host.lan. 3600 IN A 10.0.0.12"`, true, "10.0.0.12", "host.lan"},
		{"ptr skipped", `local-data-ptr: "10.0.0.10 nas.lan"`, false, "", ""},
		{"txt skipped", `local-data: "x.lan. IN TXT hello"`, false, "", ""},
		{"not unbound", `10.0.0.10 nas.lan`, false, "", ""},
		{"comment", `# local-data: "x.lan. A 1.2.3.4"`, false, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, ok := parseUnboundLine(c.line)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v (line %q)", ok, c.wantOK, c.line)
			}
			if !ok {
				return
			}
			if r.IP != c.wantIP || r.Name != c.wantName {
				t.Fatalf("got {%q %q}, want {%q %q}", r.IP, r.Name, c.wantIP, c.wantName)
			}
		})
	}
}

func TestParseAdGuardRewrites(t *testing.T) {
	body := []byte(`[
		{"domain":"nas.lan","answer":"192.168.1.10"},
		{"domain":"router6.lan","answer":"fe80::1"},
		{"domain":"cname.lan","answer":"othername.lan"},
		{"domain":"*.wild.lan","answer":"192.168.1.99"},
		{"domain":"","answer":"192.168.1.50"},
		{"domain":"spaced.lan","answer":"  192.168.1.11  "}
	]`)
	got, err := parseAdGuardRewrites(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Keep only A/AAAA answers with a real, non-wildcard domain: nas, router6, spaced.
	want := map[string]string{
		"192.168.1.10": "nas.lan",
		"fe80::1":      "router6.lan",
		"192.168.1.11": "spaced.lan",
	}
	assertRecords(t, got, want)
}

func TestParsePiholeHosts(t *testing.T) {
	body := []byte(`{"config":{"dns":{"hosts":[
		"10.0.0.20 nas.lan",
		"10.0.0.21 printer.lan printer",
		"127.0.0.1 localhost",
		"garbage-line"
	]}}}`)
	got, err := parsePiholeHosts(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	assertRecords(t, got, map[string]string{
		"10.0.0.20": "nas.lan",
		"10.0.0.21": "printer.lan",
	})
}

func TestParseTechnitium(t *testing.T) {
	zones := []byte(`{"status":"ok","response":{"zones":[
		{"name":"lan","internal":false},
		{"name":"0.in-addr.arpa","internal":true}
	]}}`)
	zs, err := parseTechnitiumZones(zones)
	if err != nil {
		t.Fatalf("zones: %v", err)
	}
	if len(zs) != 1 || zs[0] != "lan" {
		t.Fatalf("zones = %v, want [lan] (internal skipped)", zs)
	}

	recs := []byte(`{"response":{"records":[
		{"name":"nas.lan","type":"A","rData":{"ipAddress":"10.0.0.30"}},
		{"name":"router6.lan","type":"AAAA","rData":{"ipAddress":"fd00::9"}},
		{"name":"lan","type":"SOA","rData":{}},
		{"name":"www.lan","type":"CNAME","rData":{}}
	]}}`)
	got, err := parseTechnitiumRecords(recs)
	if err != nil {
		t.Fatalf("records: %v", err)
	}
	assertRecords(t, got, map[string]string{
		"10.0.0.30": "nas.lan",
		"fd00::9":   "router6.lan",
	})
}

func TestParseTechnitiumZonesError(t *testing.T) {
	if _, err := parseTechnitiumZones([]byte(`{"status":"error","errorMessage":"invalid token"}`)); err == nil {
		t.Fatal("expected error on non-ok status")
	}
}

func TestParseBadJSON(t *testing.T) {
	if _, err := parseAdGuardRewrites([]byte("not json")); err == nil {
		t.Fatal("expected error on bad AdGuard JSON")
	}
	if _, err := parsePiholeHosts([]byte("not json")); err == nil {
		t.Fatal("expected error on bad Pi-hole JSON")
	}
}

func assertRecords(t *testing.T, got []record, want map[string]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d records, want %d: %+v", len(got), len(want), got)
	}
	for _, r := range got {
		if want[r.IP] != r.Name {
			t.Errorf("IP %s -> %q, want %q", r.IP, r.Name, want[r.IP])
		}
	}
}

// nopAppender satisfies observation.Appender for driving runOnce in a test.
type nopAppender struct{}

func (nopAppender) Append(context.Context, observation.Observation) (int64, error) { return 1, nil }

func TestRunOnceHalfConfiguredServerFails(t *testing.T) {
	sink := observation.NewSink("dns-test", nopAppender{})
	// A server URL with no type selected must surface as a failure, not a silent
	// no-op (no hosts files either, so there's nothing else to succeed on).
	c := New(Config{ServerURL: "http://dns.lan:3000"})
	c.runOnce(context.Background(), sink)
	if got := c.Status().State; got != "error" {
		t.Fatalf("state = %q, want error for URL-without-type", got)
	}

	// The reverse: a type with no URL is also a misconfig.
	c = New(Config{ServerType: ServerAdGuard})
	c.runOnce(context.Background(), sink)
	if got := c.Status().State; got != "error" {
		t.Fatalf("state = %q, want error for type-without-URL", got)
	}
}
