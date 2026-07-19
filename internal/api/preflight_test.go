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
