package active

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

func TestEnumerateTargets(t *testing.T) {
	// /30 → 2 usable hosts (network + broadcast skipped).
	targets, _, err := enumerateTargets([]string{"10.0.0.0/30"})
	if err != nil {
		t.Fatal(err)
	}
	if got := addrStrings(targets); len(got) != 2 || got[0] != "10.0.0.1" || got[1] != "10.0.0.2" {
		t.Errorf("/30 = %v, want [10.0.0.1 10.0.0.2]", got)
	}

	// /31 → both addresses usable (point-to-point).
	t31, _, _ := enumerateTargets([]string{"10.0.0.0/31"})
	if got := addrStrings(t31); len(got) != 2 || got[0] != "10.0.0.0" {
		t.Errorf("/31 = %v, want 2 incl 10.0.0.0", got)
	}

	// /32 → single host.
	t32, _, _ := enumerateTargets([]string{"10.0.0.7/32"})
	if got := addrStrings(t32); len(got) != 1 || got[0] != "10.0.0.7" {
		t.Errorf("/32 = %v, want [10.0.0.7]", got)
	}

	// IPv6 prefixes are skipped (can't enumerate).
	_, skipped, _ := enumerateTargets([]string{"fe80::/64"})
	if len(skipped) != 1 {
		t.Errorf("ipv6 should be skipped, skipped=%v", skipped)
	}
}

func TestEnumerateBudgetCap(t *testing.T) {
	// Two /16s (65534 each) exceed maxTargets together; the second is skipped,
	// not silently truncated.
	targets, skipped, err := enumerateTargets([]string{"10.0.0.0/16", "10.1.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 65534 {
		t.Errorf("targets = %d, want 65534 (first /16 only)", len(targets))
	}
	if len(skipped) != 1 {
		t.Errorf("expected the 2nd /16 to be reported as skipped, got %v", skipped)
	}
}

func TestLimiterPaces(t *testing.T) {
	l := newLimiter(1000) // 1ms spacing
	cur := time.Unix(100, 0)
	var slept []time.Duration
	l.now = func() time.Time { return cur }
	l.sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); cur = cur.Add(d); return nil }

	ctx := context.Background()
	_ = l.wait(ctx) // first grant is immediate
	_ = l.wait(ctx) // second must wait one interval
	_ = l.wait(ctx)
	if len(slept) != 2 || slept[0] != time.Millisecond || slept[1] != time.Millisecond {
		t.Errorf("pacing wrong: %v (want two 1ms waits)", slept)
	}
}

func TestProbeTCPOpenWithBanner(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.0\r\n"))
		time.Sleep(50 * time.Millisecond)
		c.Close()
	}()

	port := mustPort(t, ln.Addr().String())
	res := probeTCP(context.Background(), "127.0.0.1", port, 2*time.Second, time.Second, netip.Addr{})
	if !res.open {
		t.Fatal("expected open")
	}
	if res.banner != "SSH-2.0-OpenSSH_9.0" {
		t.Errorf("banner = %q, want SSH-2.0-OpenSSH_9.0", res.banner)
	}
}

func TestProbeTCPRefused(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := mustPort(t, ln.Addr().String())
	ln.Close() // now nothing is listening on that port → connect refused

	res := probeTCP(context.Background(), "127.0.0.1", port, time.Second, 200*time.Millisecond, netip.Addr{})
	if res.open {
		t.Error("closed port should not be open")
	}
	if !res.refused {
		t.Error("closed loopback port should refuse (RST → host alive, port closed)")
	}
	if !res.alive() {
		t.Error("a refused connection still proves the host is alive")
	}
}

func TestResolveSourceIP(t *testing.T) {
	// Auto-detect should yield a usable, non-loopback IPv4 (the default-route
	// interface). On a host with no default route this may fail — tolerate that.
	if addr, desc, err := resolveSourceIP(""); err == nil {
		if !addr.Is4() || addr.IsLoopback() {
			t.Errorf("default source ip = %v (%s), want a routable IPv4", addr, desc)
		}
	}
	// A bogus interface name must error rather than bind to anything.
	if _, _, err := resolveSourceIP("definitely-not-a-nic0"); err == nil {
		t.Error("unknown interface should error, not silently bind elsewhere")
	}
}

func TestParseProcNetARP(t *testing.T) {
	data := "IP address       HW type     Flags       HW address            Mask     Device\n" +
		"10.0.0.1         0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0\n" +
		"10.0.0.2         0x1         0x0         00:00:00:00:00:00     *        eth0\n"
	m := parseProcNetARP(data)
	if m["10.0.0.1"] != "aa:bb:cc:dd:ee:01" {
		t.Errorf("10.0.0.1 → %q", m["10.0.0.1"])
	}
	if _, ok := m["10.0.0.2"]; ok {
		t.Error("incomplete (all-zero MAC) entry should be dropped")
	}
}

func TestParseArpDashA(t *testing.T) {
	data := "? (10.0.0.1) at aa:bb:cc:dd:ee:01 on en0 ifscope [ethernet]\n" +
		"? (10.0.0.5) at (incomplete) on en0 [ethernet]\n"
	m := parseArpDashA(data)
	if m["10.0.0.1"] != "aa:bb:cc:dd:ee:01" {
		t.Errorf("10.0.0.1 → %q", m["10.0.0.1"])
	}
	if _, ok := m["10.0.0.5"]; ok {
		t.Error("incomplete entry should be dropped")
	}
}

func TestSNMPEncodeDecode(t *testing.T) {
	// berOID for sysName must match the canonical encoding.
	oid, err := berOID(oidSysName)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00}
	if string(oid) != string(want) {
		t.Errorf("berOID(sysName) = % x, want % x", oid, want)
	}

	// Build a GetResponse carrying sysName="router1" and decode it back.
	val := tlv(0x04, []byte("router1"))
	vb := tlv(0x30, append(append([]byte{}, oid...), val...))
	vbl := tlv(0x30, vb)
	pdu := tlv(0xa2, concat(berInt(7), berInt(0), berInt(0), vbl))
	msg := tlv(0x30, concat(berInt(1), tlv(0x04, []byte("public")), pdu))

	got, err := parseSNMPStringValue(msg)
	if err != nil {
		t.Fatal(err)
	}
	if got != "router1" {
		t.Errorf("decoded sysName = %q, want router1", got)
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func addrStrings(targets []netip.Addr) []string {
	out := make([]string, len(targets))
	for i, a := range targets {
		out[i] = a.String()
	}
	return out
}

func mustPort(t *testing.T, hostport string) int {
	t.Helper()
	_, p, err := net.SplitHostPort(hostport)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
