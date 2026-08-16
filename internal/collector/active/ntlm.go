package active

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// Windows identity from an NTLMSSP CHALLENGE (ported from IP Recon 1.5 M3a).
//
// Windows answers an unauthenticated NTLM negotiation with a CHALLENGE message
// that states its own OS major.minor.build, plus its NetBIOS and DNS names. No
// credentials are sent or needed: we stop at the CHALLENGE and never attempt an
// AUTHENTICATE, so this reads a greeting rather than trying a login.
//
// TWO THINGS IP RECON LEARNED THE HARD WAY, both encoded below.
//
//  1. THE BUILD IS USUALLY IN THE VERSION FIELD AT OFFSET 48, not in the
//     MsvAvOsVersion AvPair. Their parser read only the AvPair, and both live
//     Windows 11 hosts measured on 2026-08-14
//     omitted it entirely while sending `10.0 build 26100` at offset 48.
//     The exact build was on the wire in every response and discarded.
//
//  2. THE VERSION FIELD IS ONLY THERE WHEN THE FLAGS SAY SO. Those eight bytes
//     are payload unless NTLMSSP_NEGOTIATE_VERSION is set in NegotiateFlags —
//     read unconditionally they decode as garbage.
//
// Both transports lead to the same CHALLENGE. SMB (445) wraps it in SPNEGO
// inside an SMB2 SESSION_SETUP; RDP (3389) wraps it in CredSSP inside TLS. We
// try whichever port the scan already found open.

// ntlmResult is what a CHALLENGE stated about the host.
type ntlmResult struct {
	osVersion   string // "11 24H2 (build 26100)" — bare, composes after "Windows"
	netbiosName string
	dnsName     string
	dnsDomain   string
	build       uint16
}

func (r ntlmResult) empty() bool {
	return r.osVersion == "" && r.netbiosName == "" && r.dnsName == ""
}

// hostname returns the best name the CHALLENGE offered: the DNS computer name
// when present (it is fully qualified), else the NetBIOS name.
func (r ntlmResult) hostname() string {
	if r.dnsName != "" {
		return r.dnsName
	}
	return r.netbiosName
}

// probeNTLM tries the transports the open-port scan justifies and returns the
// first CHALLENGE that parses. A host that answers neither yields nothing —
// absence is never recorded as a fact.
func probeNTLM(ctx context.Context, ip string, smbOpen, rdpOpen bool, timeout time.Duration, localIP netip.Addr) *ntlmResult {
	if smbOpen {
		if r := probeNTLMOverSMB(ctx, ip, timeout, localIP); r != nil && !r.empty() {
			return r
		}
	}
	if rdpOpen {
		if r := probeNTLMOverRDP(ctx, ip, timeout, localIP); r != nil && !r.empty() {
			return r
		}
	}
	return nil
}

// ── the NTLMSSP messages ─────────────────────────────────────────────────────

var ntlmSignature = []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0}

// Flags we advertise. NEGOTIATE_VERSION is the one that matters here: it asks
// the server to include its own Version field in the reply, which is where the
// build number actually lives.
const (
	ntlmNegotiateUnicode   = 0x00000001
	ntlmRequestTarget      = 0x00000004
	ntlmNegotiateNTLM      = 0x00000200
	ntlmNegotiateAlwaysSig = 0x00008000
	ntlmNegotiateExtSec    = 0x00080000
	ntlmNegotiateVersion   = 0x02000000
)

// ntlmNegotiate builds a Type 1 NEGOTIATE message. Domain and workstation are
// left empty — we are not authenticating, and naming ourselves would tell the
// target more than it tells us.
func ntlmNegotiate() []byte {
	msg := make([]byte, 32)
	copy(msg, ntlmSignature)
	binary.LittleEndian.PutUint32(msg[8:], 1) // MessageType = NEGOTIATE
	binary.LittleEndian.PutUint32(msg[12:], ntlmNegotiateUnicode|ntlmRequestTarget|
		ntlmNegotiateNTLM|ntlmNegotiateAlwaysSig|ntlmNegotiateExtSec|ntlmNegotiateVersion)
	// DomainNameFields (16..23) and WorkstationFields (24..31) stay zero.
	return msg
}

// findNTLMChallenge locates and parses the CHALLENGE inside an arbitrary reply.
//
// Deliberately a SEARCH rather than an ASN.1 descent. The message arrives inside
// SPNEGO inside SMB2, or inside CredSSP inside TLS, and both wrappers vary by
// server version and dialect. The signature plus a MessageType of 2 plus the
// structural bounds checks below are a stronger guarantee than a hand-rolled DER
// parser that has to be right about every optional field.
func findNTLMChallenge(data []byte) *ntlmResult {
	i := bytes.Index(data, ntlmSignature)
	if i < 0 {
		return nil
	}
	return parseNTLMChallenge(data[i:])
}

// parseNTLMChallenge decodes a Type 2 CHALLENGE. Returns nil for anything that
// is not a well-formed challenge.
func parseNTLMChallenge(d []byte) *ntlmResult {
	// The fixed header runs to offset 48; the Version field occupies 48..55.
	if len(d) < 48 || !bytes.Equal(d[:8], ntlmSignature) {
		return nil
	}
	if binary.LittleEndian.Uint32(d[8:]) != 2 { // MessageType = CHALLENGE
		return nil
	}
	res := &ntlmResult{}

	var major, minor uint8
	var build uint16
	var haveVersion bool

	// TargetInfo (offset 40): length + offset of the AvPair list.
	tiLen := int(binary.LittleEndian.Uint16(d[40:]))
	tiOff := int(binary.LittleEndian.Uint32(d[44:]))
	if tiLen > 0 && tiOff >= 0 && tiOff+tiLen <= len(d) {
		major, minor, build, haveVersion = parseNTLMTargetInfo(d[tiOff:tiOff+tiLen], res)
	}

	// Version field at offset 48 — present ONLY when the flags say so. This is
	// the read that was missing in IP Recon, and it is the one that fires on
	// real hardware; MsvAvOsVersion above is the rarer, more explicit statement
	// and keeps precedence when both are present.
	flags := binary.LittleEndian.Uint32(d[20:])
	if !haveVersion && flags&ntlmNegotiateVersion != 0 && len(d) >= 56 {
		// A real Windows always reports major >= 5 (2000 and later). Zeroes mean
		// the server set the flag and filled the field with padding.
		if d[48] >= 5 && binary.LittleEndian.Uint16(d[50:]) > 0 {
			major, minor, build, haveVersion = d[48], d[49], binary.LittleEndian.Uint16(d[50:]), true
		}
	}

	if haveVersion {
		res.build = build
		res.osVersion = windowsRelease(major, minor, build)
	}
	if res.empty() {
		return nil
	}
	return res
}

// parseNTLMTargetInfo walks the AvPair list, filling in the names and returning
// the version from MsvAvOsVersion when the server sent one.
func parseNTLMTargetInfo(d []byte, res *ntlmResult) (major, minor uint8, build uint16, ok bool) {
	for len(d) >= 4 {
		id := binary.LittleEndian.Uint16(d)
		n := int(binary.LittleEndian.Uint16(d[2:]))
		d = d[4:]
		if id == 0x0000 { // MsvAvEOL
			break
		}
		if n > len(d) {
			break
		}
		v := d[:n]
		switch id {
		case 0x0001: // MsvAvNbComputerName
			res.netbiosName = utf16LE(v)
		case 0x0003: // MsvAvDnsComputerName
			res.dnsName = utf16LE(v)
		case 0x0004: // MsvAvDnsDomainName
			res.dnsDomain = utf16LE(v)
		case 0x000D: // MsvAvOsVersion — major, minor, build(LE), reserved
			if len(v) >= 4 {
				major, minor, build, ok = v[0], v[1], binary.LittleEndian.Uint16(v[2:]), true
			}
		}
		d = d[n:]
	}
	return major, minor, build, ok
}

// windowsRelease maps a version triple to a BARE release string that composes
// after "Windows" — "11 24H2 (build 26100)".
//
// ORDER MATTERS AND THE OVERLAP IS REAL. Server and client build numbers
// interleave, so the server ranges must be tested before the Windows 11 ones:
// Server 2022 23H2 is build 25398, which is higher than Windows 11 23H2's
// 22631 and would otherwise read as a client release.
//
// Where a build genuinely cannot distinguish the two, the string says so rather
// than picking. 26100 is the base for both Windows 11 24H2 and Server 2025;
// naming one of them would be a coin flip presented as a finding.
func windowsRelease(major, minor uint8, build uint16) string {
	withBuild := func(name string) string {
		return name + " (build " + strconv.Itoa(int(build)) + ")"
	}
	if major == 10 {
		switch {
		// Server builds inside the Windows 11 range — checked first.
		case build >= 26040 && build < 26100:
			return withBuild("Server 2025")
		case build >= 25398 && build < 26040:
			return withBuild("Server 2022 23H2")
		// Windows 11. 25H2 (26200) is client-only — Server 2025 stayed on the
		// 26100 base — so 26200+ is unambiguous.
		case build >= 26200:
			return withBuild("11 25H2")
		case build >= 26100:
			return withBuild("11 24H2 / Server 2025")
		case build >= 22631:
			return withBuild("11 23H2")
		case build >= 22621:
			return withBuild("11 22H2")
		case build >= 22000:
			return withBuild("11 21H2")
		// Server builds below the Windows 11 range.
		case build >= 20348:
			return withBuild("Server 2022")
		// Windows 10.
		case build >= 19045:
			return withBuild("10 22H2")
		case build >= 19044:
			return withBuild("10 21H2")
		case build >= 19043:
			return withBuild("10 21H1")
		case build >= 19042:
			return withBuild("10 20H2")
		case build >= 19041:
			return withBuild("10 2004")
		case build >= 18363:
			return withBuild("10 1909")
		case build >= 18362:
			return withBuild("10 1903")
		case build >= 17763:
			return withBuild("10 1809 / Server 2019")
		case build >= 17134:
			return withBuild("10 1803")
		case build >= 16299:
			return withBuild("10 1709")
		case build >= 15063:
			return withBuild("10 1703")
		case build >= 14393:
			return withBuild("10 1607 / Server 2016")
		case build >= 10586:
			return withBuild("10 1511")
		case build >= 10240:
			return withBuild("10 1507")
		}
	}
	if major == 6 {
		switch minor {
		case 3:
			return withBuild("8.1 / Server 2012 R2")
		case 2:
			return withBuild("8 / Server 2012")
		case 1:
			return withBuild("7 / Server 2008 R2")
		case 0:
			return withBuild("Vista / Server 2008")
		}
	}
	// An unmapped triple still states the build, which is always true.
	return "(build " + strconv.Itoa(int(build)) + ")"
}

func utf16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return strings.TrimSpace(string(utf16.Decode(u)))
}

// ── SMB2 transport (445) ─────────────────────────────────────────────────────

// probeNTLMOverSMB runs SMB2 NEGOTIATE then SESSION_SETUP carrying an NTLMSSP
// NEGOTIATE inside SPNEGO. The server replies STATUS_MORE_PROCESSING_REQUIRED
// with the CHALLENGE — the exchange stops there.
func probeNTLMOverSMB(ctx context.Context, ip string, timeout time.Duration, localIP netip.Addr) *ntlmResult {
	conn, err := dialProbe(ctx, ip, 445, timeout, localIP)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if err := writeNetBIOS(conn, smb2Negotiate()); err != nil {
		return nil
	}
	if _, err := readNetBIOS(conn); err != nil {
		return nil
	}
	if err := writeNetBIOS(conn, smb2SessionSetup(spnegoNegTokenInit(ntlmNegotiate()))); err != nil {
		return nil
	}
	resp, err := readNetBIOS(conn)
	if err != nil {
		return nil
	}
	return findNTLMChallenge(resp)
}

// smb2Header builds the fixed 64-byte SMB2 header for one command.
func smb2Header(command uint16, messageID uint64) []byte {
	h := make([]byte, 64)
	copy(h, []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(h[4:], 64) // StructureSize
	binary.LittleEndian.PutUint16(h[12:], command)
	binary.LittleEndian.PutUint16(h[14:], 1) // CreditRequest
	binary.LittleEndian.PutUint64(h[24:], messageID)
	return h
}

// smb2Negotiate offers only the two dialects every SMB2 server understands. We
// are not going to transfer data, so there is nothing to gain from negotiating
// up to 3.1.1 and its extra negotiate contexts.
func smb2Negotiate() []byte {
	body := make([]byte, 36+4)
	binary.LittleEndian.PutUint16(body[0:], 36) // StructureSize
	binary.LittleEndian.PutUint16(body[2:], 2)  // DialectCount
	binary.LittleEndian.PutUint16(body[4:], 1)  // SecurityMode: signing enabled
	binary.LittleEndian.PutUint16(body[36:], 0x0202)
	binary.LittleEndian.PutUint16(body[38:], 0x0210)
	return append(smb2Header(0x0000, 0), body...)
}

// smb2SessionSetup carries the SPNEGO blob in the security buffer.
func smb2SessionSetup(secBlob []byte) []byte {
	body := make([]byte, 24)
	binary.LittleEndian.PutUint16(body[0:], 25) // StructureSize (24 + variable)
	body[3] = 1                                 // SecurityMode: signing enabled
	binary.LittleEndian.PutUint16(body[12:], 64+24)
	binary.LittleEndian.PutUint16(body[14:], uint16(len(secBlob)))
	return append(append(smb2Header(0x0001, 1), body...), secBlob...)
}

// writeNetBIOS frames a message with the 4-byte NetBIOS session header SMB uses
// over 445: one zero byte then a 24-bit big-endian length.
func writeNetBIOS(w io.Writer, msg []byte) error {
	hdr := []byte{0, byte(len(msg) >> 16), byte(len(msg) >> 8), byte(len(msg))}
	_, err := w.Write(append(hdr, msg...))
	return err
}

// readNetBIOS reads one framed message, capped so a hostile or confused peer
// cannot make us allocate arbitrarily.
func readNetBIOS(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if n <= 0 || n > 64<<10 {
		return nil, errors.New("ntlm: implausible NetBIOS frame length")
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

// ── SPNEGO / DER ─────────────────────────────────────────────────────────────

var (
	oidSPNEGO = []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}                         // 1.3.6.1.5.5.2
	oidNTLMSS = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a} // 1.3.6.1.4.1.311.2.2.10
)

// spnegoNegTokenInit wraps an NTLMSSP message in the GSS-API InitialContextToken
// that SMB2 SESSION_SETUP expects.
func spnegoNegTokenInit(ntlm []byte) []byte {
	mechTypes := derTag(0x30, derTag(0x06, oidNTLMSS))    // SEQUENCE OF OID
	inner := derTag(0x30, append(derTag(0xA0, mechTypes), // [0] mechTypes
		derTag(0xA2, derTag(0x04, ntlm))...)) // [2] mechToken
	body := append(derTag(0x06, oidSPNEGO), derTag(0xA0, inner)...)
	return derTag(0x60, body) // [APPLICATION 0]
}

// derTag wraps content in a DER tag with a definite length.
func derTag(tag byte, content []byte) []byte {
	out := []byte{tag}
	n := len(content)
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, content...)
}

// ── RDP transport (3389) ─────────────────────────────────────────────────────

// probeNTLMOverRDP negotiates RDP up to TLS, then sends a CredSSP TSRequest
// carrying the NTLMSSP NEGOTIATE. The server's TSRequest reply holds the
// CHALLENGE.
//
// TLS verification is off for this connection only: RDP hosts serve a
// self-signed certificate by default, and this probe reads a version string
// rather than making a trust decision. Nothing is sent over the channel except
// the NEGOTIATE message.
func probeNTLMOverRDP(ctx context.Context, ip string, timeout time.Duration, localIP netip.Addr) *ntlmResult {
	conn, err := dialProbe(ctx, ip, 3389, timeout, localIP)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// X.224 connection request asking for TLS or CredSSP ("hybrid").
	if _, err := conn.Write(x224ConnectionRequest()); err != nil {
		return nil
	}
	resp, err := readTPKT(conn)
	if err != nil || !rdpOffersTLS(resp) {
		return nil
	}

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: ip}) //nolint:gosec // see doc comment
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil
	}
	_ = tlsConn.SetDeadline(time.Now().Add(timeout))

	if _, err := tlsConn.Write(credSSPRequest(ntlmNegotiate())); err != nil {
		return nil
	}
	buf := make([]byte, 8<<10)
	n, err := tlsConn.Read(buf)
	if err != nil && n == 0 {
		return nil
	}
	return findNTLMChallenge(buf[:n])
}

// x224ConnectionRequest asks for PROTOCOL_SSL|PROTOCOL_HYBRID. A host that
// requires NLA answers with HYBRID; one that merely allows TLS answers SSL.
func x224ConnectionRequest() []byte {
	neg := []byte{0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00} // type, flags, len(LE), SSL|HYBRID
	x224 := append([]byte{byte(6 + len(neg)), 0xE0, 0, 0, 0, 0, 0}, neg...)
	tpkt := []byte{0x03, 0x00, 0, 0}
	binary.BigEndian.PutUint16(tpkt[2:], uint16(4+len(x224)))
	return append(tpkt, x224...)
}

// rdpOffersTLS reports whether the negotiation response selected a protocol we
// can continue on.
//
// Read at a FIXED OFFSET, not by searching for the 0x02 type byte: the X.224
// Connection Confirm in front of it carries two reference fields that can
// themselves contain 0x02, so a scan would match the wrong byte and read a
// protocol out of a destination reference. The Connection Confirm is LI plus six
// bytes, so the negotiation response begins at offset 7:
//
//	type(1) flags(1) length(2)=8 selectedProtocol(4)
//
// Type 0x02 is RDP_NEG_RSP; 0x03 is RDP_NEG_FAILURE, and a host that answers
// with neither (a bare Connection Confirm, i.e. standard RDP security) is simply
// not one we can read a CHALLENGE from.
func rdpOffersTLS(resp []byte) bool {
	const negOffset = 7
	if len(resp) < negOffset+8 {
		return false
	}
	r := resp[negOffset:]
	if r[0] != 0x02 || binary.LittleEndian.Uint16(r[2:]) != 8 {
		return false
	}
	selected := binary.LittleEndian.Uint32(r[4:])
	return selected == 1 || selected == 2 // PROTOCOL_SSL | PROTOCOL_HYBRID
}

// readTPKT reads one TPKT-framed message (03 00 <len16> …).
func readTPKT(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != 0x03 {
		return nil, errors.New("ntlm: not a TPKT frame")
	}
	n := int(binary.BigEndian.Uint16(hdr[2:])) - 4
	if n <= 0 || n > 8<<10 {
		return nil, errors.New("ntlm: implausible TPKT length")
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

// credSSPRequest builds a TSRequest carrying one NTLMSSP token:
//
//	TSRequest ::= SEQUENCE { version [0] INTEGER, negoTokens [1] NegoData }
//	NegoData  ::= SEQUENCE OF SEQUENCE { negoToken [0] OCTET STRING }
func credSSPRequest(ntlm []byte) []byte {
	version := derTag(0xA0, []byte{0x02, 0x01, 0x06}) // [0] INTEGER 6
	token := derTag(0x30, derTag(0xA0, derTag(0x04, ntlm)))
	negoTokens := derTag(0xA1, derTag(0x30, token))
	return derTag(0x30, append(version, negoTokens...))
}

// dialProbe opens a TCP connection pinned to the management interface, matching
// the egress discipline the rest of the prober follows.
func dialProbe(ctx context.Context, ip string, port int, timeout time.Duration, localIP netip.Addr) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	if localIP.IsValid() {
		d.LocalAddr = &net.TCPAddr{IP: localIP.AsSlice()}
	}
	return d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
}
