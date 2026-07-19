package api

import (
	"context"
	"strings"
	"testing"
)

func TestParseResolvConf(t *testing.T) {
	content := `# managed by systemd-resolved
nameserver 192.168.10.2
nameserver 192.168.10.3    # mirage
search lan
   nameserver 1.1.1.1
options edns0
`
	got := parseResolvConf(content)
	want := []string{"192.168.10.2", "192.168.10.3", "1.1.1.1"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("parseResolvConf = %v, want %v", got, want)
	}
}

func TestPreflightURLSkipsIPsAndEmpty(t *testing.T) {
	ctx := context.Background()
	// These need no DNS — must return nil without touching the resolver.
	for _, in := range []string{
		"",                         // empty
		"http://192.168.10.2:5380", // IP literal + port (Technitium)
		"192.168.10.2",             // scheme-less IP
		"https://[fd00::5]:8006",   // IPv6 literal
		"http://10.0.0.1",          // bare IP URL
	} {
		if err := preflightURL(ctx, in); err != nil {
			t.Errorf("preflightURL(%q) = %v, want nil (no DNS needed)", in, err)
		}
	}
	// A hostname that won't resolve → the friendly error, even scheme-less.
	if err := preflightURL(ctx, "http://tessera-nope.invalid:3000"); err == nil {
		t.Error("expected a resolve error for an unresolvable hostname URL")
	}
	if err := preflightURL(ctx, "tessera-nope.invalid:8006"); err == nil {
		t.Error("expected a resolve error for a scheme-less unresolvable host")
	}
}

func TestPreflightHostSkipsIPs(t *testing.T) {
	ctx := context.Background()
	for _, ip := range []string{"192.168.10.3", "fd00::3", ""} {
		if err := preflightHost(ctx, ip); err != nil {
			t.Errorf("preflightHost(%q) = %v, want nil", ip, err)
		}
	}
}

func TestPreflightResolveFailsFriendly(t *testing.T) {
	// .invalid is a reserved TLD guaranteed never to resolve (RFC 2606), so this
	// exercises the failure path deterministically without depending on network.
	err := preflightResolve(context.Background(), "tessera-nonexistent.invalid")
	if err == nil {
		t.Fatal("expected an error for an unresolvable host")
	}
	msg := err.Error()
	if !strings.Contains(msg, "couldn't resolve") || !strings.Contains(msg, "not the API key") {
		t.Errorf("error not the friendly DNS message: %q", msg)
	}
}
