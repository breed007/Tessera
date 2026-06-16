package active

import (
	"context"
	"net"
	"strings"
)

// reverseDNS resolves the PTR record for ip and returns the first name (trailing
// dot stripped). It uses the system resolver; failures yield "".
func reverseDNS(ctx context.Context, ip string) string {
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(strings.TrimSpace(names[0]), ".")
}
