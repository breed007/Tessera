package dns

import "testing"

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
	if len(got) != len(want) {
		t.Fatalf("got %d records, want %d: %+v", len(got), len(want), got)
	}
	for _, r := range got {
		if want[r.IP] != r.Name {
			t.Errorf("IP %s -> %q, want %q", r.IP, r.Name, want[r.IP])
		}
	}
}

func TestParseAdGuardRewritesBadJSON(t *testing.T) {
	if _, err := parseAdGuardRewrites([]byte("not json")); err == nil {
		t.Fatal("expected error on bad JSON")
	}
}
