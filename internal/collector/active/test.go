package active

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

// TestSNMP verifies an SNMP community against a device (§M10 settings test) by
// reading sysName. A nil error with a name means the community works.
func TestSNMP(ctx context.Context, ip, community string) (string, error) {
	if _, err := netip.ParseAddr(ip); err != nil {
		return "", errors.New("enter a device IP to test against")
	}
	if community == "" {
		return "", errors.New("community string is empty")
	}
	name, err := snmpGet(ctx, ip, community, oidSysName, 4*time.Second, netip.Addr{})
	if err != nil {
		return "", err
	}
	if name == "" {
		return "", errors.New("no response (wrong community, SNMP disabled, or unreachable)")
	}
	return name, nil
}
