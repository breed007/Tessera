package active

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// buildChallenge assembles a CHALLENGE in the two shapes seen on the wire: with
// the Version field at offset 48 (what real Windows 11 hosts sent), with an
// MsvAvOsVersion AvPair, or with neither.
func buildChallenge(major, minor byte, build uint16, withVersionField, withAvPair bool, netbios string) []byte {
	var ti bytes.Buffer
	av := func(id uint16, v []byte) {
		binary.Write(&ti, binary.LittleEndian, id)
		binary.Write(&ti, binary.LittleEndian, uint16(len(v)))
		ti.Write(v)
	}
	if netbios != "" {
		av(0x0001, utf16LEBytes(netbios))
	}
	if withAvPair {
		p := make([]byte, 8)
		p[0], p[1] = major, minor
		binary.LittleEndian.PutUint16(p[2:], build)
		av(0x000D, p)
	}
	av(0x0000, nil) // MsvAvEOL

	msg := make([]byte, 56)
	copy(msg, ntlmSignature)
	binary.LittleEndian.PutUint32(msg[8:], 2) // CHALLENGE
	var flags uint32 = ntlmNegotiateUnicode | ntlmNegotiateNTLM
	if withVersionField {
		flags |= ntlmNegotiateVersion
		msg[48], msg[49] = major, minor
		binary.LittleEndian.PutUint16(msg[50:], build)
	}
	binary.LittleEndian.PutUint32(msg[20:], flags)
	binary.LittleEndian.PutUint16(msg[40:], uint16(ti.Len()))
	binary.LittleEndian.PutUint16(msg[42:], uint16(ti.Len()))
	binary.LittleEndian.PutUint32(msg[44:], 56) // TargetInfo starts after the header
	return append(msg, ti.Bytes()...)
}

func utf16LEBytes(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, r := range u {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return b
}

// The case that motivated the port: the AvPair is absent and the build is in the
// Version field at offset 48. IP Recon read only the AvPair and lost it.
func TestChallengeReadsBuildFromVersionField(t *testing.T) {
	r := parseNTLMChallenge(buildChallenge(10, 0, 26100, true, false, "WORKSTATION01"))
	if r == nil {
		t.Fatal("challenge did not parse")
	}
	if r.build != 26100 {
		t.Errorf("build = %d, want 26100", r.build)
	}
	if r.osVersion != "11 24H2 / Server 2025 (build 26100)" {
		t.Errorf("osVersion = %q", r.osVersion)
	}
	if r.netbiosName != "WORKSTATION01" {
		t.Errorf("netbiosName = %q", r.netbiosName)
	}
}

// MsvAvOsVersion is the more explicit statement and keeps precedence.
func TestChallengeAvPairWinsOverVersionField(t *testing.T) {
	msg := buildChallenge(10, 0, 19045, false, true, "")
	// Also stamp a DIFFERENT build into the version field; the AvPair must win.
	binary.LittleEndian.PutUint32(msg[20:], binary.LittleEndian.Uint32(msg[20:])|ntlmNegotiateVersion)
	msg[48], msg[49] = 10, 0
	binary.LittleEndian.PutUint16(msg[50:], 22631)
	r := parseNTLMChallenge(msg)
	if r == nil || r.build != 19045 {
		t.Fatalf("build = %v, want 19045 (the AvPair)", r)
	}
}

// Without NEGOTIATE_VERSION those eight bytes are payload, not a version.
func TestChallengeIgnoresVersionFieldWhenFlagUnset(t *testing.T) {
	msg := buildChallenge(10, 0, 26100, false, false, "PC1")
	msg[48], msg[49] = 10, 0
	binary.LittleEndian.PutUint16(msg[50:], 26100)
	r := parseNTLMChallenge(msg)
	if r == nil {
		t.Fatal("expected the names to still parse")
	}
	if r.osVersion != "" || r.build != 0 {
		t.Errorf("read a version from unflagged padding: %q build=%d", r.osVersion, r.build)
	}
}

func TestChallengeRejectsNonChallenges(t *testing.T) {
	if r := parseNTLMChallenge(ntlmNegotiate()); r != nil {
		t.Errorf("a NEGOTIATE parsed as a CHALLENGE: %+v", r)
	}
	if r := parseNTLMChallenge([]byte("not ntlm at all")); r != nil {
		t.Errorf("garbage parsed: %+v", r)
	}
}

// The CHALLENGE arrives buried in SPNEGO or CredSSP; the search must find it.
func TestFindChallengeInsideAWrapper(t *testing.T) {
	inner := buildChallenge(10, 0, 22631, true, false, "WS01")
	wrapped := append([]byte{0xA1, 0x81, 0x99, 0x30, 0x04, 0x02, 0x01}, inner...)
	r := findNTLMChallenge(append(wrapped, 0xDE, 0xAD))
	if r == nil || r.osVersion != "11 23H2 (build 22631)" {
		t.Fatalf("got %+v", r)
	}
}

// The server/client build ranges interleave; the overlap guard is the whole
// point of the ordering in windowsRelease.
func TestWindowsReleaseOverlapGuard(t *testing.T) {
	cases := []struct {
		build uint16
		want  string
	}{
		{26200, "11 25H2 (build 26200)"},
		{26100, "11 24H2 / Server 2025 (build 26100)"}, // genuinely ambiguous — say so
		{26040, "Server 2025 (build 26040)"},
		{25398, "Server 2022 23H2 (build 25398)"}, // higher than 11 23H2's 22631
		{22631, "11 23H2 (build 22631)"},
		{20348, "Server 2022 (build 20348)"},
		{19045, "10 22H2 (build 19045)"},
	}
	for _, c := range cases {
		if got := windowsRelease(10, 0, c.build); got != c.want {
			t.Errorf("windowsRelease(10,0,%d) = %q, want %q", c.build, got, c.want)
		}
	}
	// An unmapped triple still states the build, which is always true.
	if got := windowsRelease(11, 0, 40000); got != "(build 40000)" {
		t.Errorf("unmapped = %q", got)
	}
}

// The NEGOTIATE must ask for the version, or the server has no reason to send
// the field this whole probe exists to read.
func TestNegotiateAsksForTheVersion(t *testing.T) {
	msg := ntlmNegotiate()
	if len(msg) != 32 || !bytes.Equal(msg[:8], ntlmSignature) {
		t.Fatalf("malformed NEGOTIATE: %d bytes", len(msg))
	}
	if binary.LittleEndian.Uint32(msg[8:]) != 1 {
		t.Error("MessageType is not NEGOTIATE")
	}
	if binary.LittleEndian.Uint32(msg[12:])&ntlmNegotiateVersion == 0 {
		t.Error("NEGOTIATE_VERSION not set — the server will omit the version field")
	}
}

// The SPNEGO wrapper must be well-formed DER carrying the NTLM token, or the
// SESSION_SETUP is rejected before anything is read.
func TestSPNEGOWrapsTheToken(t *testing.T) {
	ntlm := ntlmNegotiate()
	blob := spnegoNegTokenInit(ntlm)
	if blob[0] != 0x60 {
		t.Fatalf("not an InitialContextToken: tag %#x", blob[0])
	}
	if !bytes.Contains(blob, oidSPNEGO) || !bytes.Contains(blob, oidNTLMSS) {
		t.Error("SPNEGO or NTLM mechanism OID missing")
	}
	if !bytes.Contains(blob, ntlm) {
		t.Error("the NTLM token is not inside the blob")
	}
}

// A short frame must never panic the sweep — probeHost recovers, but a parser
// that reads past its input would corrupt a scan before it got there.
func TestChallengeParserIsBoundsSafe(t *testing.T) {
	full := buildChallenge(10, 0, 26100, true, true, "PC")
	for i := 0; i < len(full); i++ {
		parseNTLMChallenge(full[:i]) // must not panic
	}
	truncatedTargetInfo := buildChallenge(10, 0, 26100, true, true, "PC")
	binary.LittleEndian.PutUint16(truncatedTargetInfo[40:], 0xFFFF) // lies about length
	parseNTLMChallenge(truncatedTargetInfo)
}

// The negotiation response must be read at its fixed offset. A destination
// reference containing 0x02 is the case a scan gets wrong.
func TestRDPOffersTLS(t *testing.T) {
	// X.224 Connection Confirm: LI, 0xD0, dst-ref(2), src-ref(2), class.
	cc := func(dstRef [2]byte, neg []byte) []byte {
		return append([]byte{byte(6 + len(neg)), 0xD0, dstRef[0], dstRef[1], 0x00, 0x00, 0x00}, neg...)
	}
	negRsp := func(typ byte, proto uint32) []byte {
		b := []byte{typ, 0x00, 0x08, 0x00, 0, 0, 0, 0}
		binary.LittleEndian.PutUint32(b[4:], proto)
		return b
	}
	cases := []struct {
		name string
		in   []byte
		want bool
	}{
		{"hybrid selected", cc([2]byte{0, 0}, negRsp(0x02, 2)), true},
		{"ssl selected", cc([2]byte{0, 0}, negRsp(0x02, 1)), true},
		{"negotiation failure", cc([2]byte{0, 0}, negRsp(0x03, 0)), false},
		{"protocol RDP (no TLS)", cc([2]byte{0, 0}, negRsp(0x02, 0)), false},
		{"bare connection confirm", cc([2]byte{0, 0}, nil), false},
		// The false-match case: 0x02 sits in the destination reference, and the
		// bytes after it are not a negotiation response at all.
		{"0x02 in the destination reference", cc([2]byte{0x02, 0x00}, nil), false},
		{"truncated", []byte{0x0E, 0xD0, 0, 0}, false},
	}
	for _, c := range cases {
		if got := rdpOffersTLS(c.in); got != c.want {
			t.Errorf("%s: rdpOffersTLS = %v, want %v", c.name, got, c.want)
		}
	}
}
