package api

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// preflightResolve checks that host resolves via the system resolver before a
// connection test that depends on it. When DNS is the real problem, Go's raw
// error blames the resolver IP ("lookup X on 192.168.10.4:53: connection
// refused"), which reads like the app is talking to the DNS server on purpose —
// so we translate it into a plain-English message that names the host's
// configured resolver(s) and points the finger at DNS, not the API key.
func preflightResolve(ctx context.Context, host string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := net.DefaultResolver.LookupHost(ctx, host); err != nil {
		hint := ""
		if ns := resolvConfServers(); len(ns) > 0 {
			hint = " The Tessera host's configured DNS server(s): " + strings.Join(ns, ", ") + " — check those are reachable and serving DNS."
		}
		return fmt.Errorf("couldn't resolve %s: this is a DNS/network problem on the Tessera host, not the API key or endpoint.%s (%v)", host, hint, err)
	}
	return nil
}

// resolvConfServers returns the nameservers from /etc/resolv.conf (best-effort;
// empty on non-Unix or unreadable).
func resolvConfServers() []string {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	return parseResolvConf(string(b))
}

func parseResolvConf(content string) []string {
	var out []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// "nameserver <ip>" — take only the address, ignoring any trailing tokens.
		if fields := strings.Fields(line); len(fields) >= 2 && fields[0] == "nameserver" {
			out = append(out, fields[1])
		}
	}
	return out
}
