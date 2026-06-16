package active

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Minimal SNMPv2c GET, hand-rolled so the prober adds no SNMP dependency. It
// supports exactly what §4.2 asks for: reading scalar OIDs like sysName and
// sysDescr when a community string is configured. Only OCTET STRING values are
// returned as text (sufficient for the system MIB scalars we query).

const (
	oidSysDescr = "1.3.6.1.2.1.1.1.0"
	oidSysName  = "1.3.6.1.2.1.1.5.0"
)

var snmpReqID uint32

// snmpGet sends a GET for oid to ip:161 with the given community and returns the
// OCTET STRING value, or "" on any error/timeout/non-string value. localIP, when
// valid, pins the request's source address to the management interface.
func snmpGet(ctx context.Context, ip, community, oid string, timeout time.Duration, localIP netip.Addr) (string, error) {
	req, err := buildSNMPGet(community, oid, int(atomic.AddUint32(&snmpReqID, 1)))
	if err != nil {
		return "", err
	}
	d := net.Dialer{Timeout: timeout}
	if localIP.IsValid() {
		d.LocalAddr = &net.UDPAddr{IP: localIP.AsSlice()}
	}
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(ip, "161"))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(req); err != nil {
		return "", err
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	return parseSNMPStringValue(buf[:n])
}

// ── BER encoding ─────────────────────────────────────────────────────────────

func tlv(tag byte, content []byte) []byte {
	out := []byte{tag}
	out = append(out, encodeLen(len(content))...)
	return append(out, content...)
}

func encodeLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
	}
	return append([]byte{0x80 | byte(len(b))}, b...)
}

func berInt(n int) []byte {
	// Minimal two's-complement; our ids/statuses are small non-negatives.
	if n == 0 {
		return tlv(0x02, []byte{0x00})
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
	}
	if b[0]&0x80 != 0 { // keep it positive
		b = append([]byte{0x00}, b...)
	}
	return tlv(0x02, b)
}

func berOID(oid string) ([]byte, error) {
	parts := strings.Split(oid, ".")
	if len(parts) < 2 {
		return nil, errors.New("snmp: oid too short")
	}
	nums := make([]int, len(parts))
	for i, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil {
			return nil, errors.New("snmp: bad oid arc")
		}
		nums[i] = v
	}
	enc := []byte{byte(nums[0]*40 + nums[1])}
	for _, v := range nums[2:] {
		enc = append(enc, base128(v)...)
	}
	return tlv(0x06, enc), nil
}

func base128(v int) []byte {
	if v == 0 {
		return []byte{0x00}
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte(v & 0x7f)}, b...)
		v >>= 7
	}
	for i := 0; i < len(b)-1; i++ {
		b[i] |= 0x80
	}
	return b
}

func buildSNMPGet(community, oid string, reqID int) ([]byte, error) {
	oidBytes, err := berOID(oid)
	if err != nil {
		return nil, err
	}
	varbind := tlv(0x30, append(oidBytes, tlv(0x05, nil)...)) // OID + NULL
	varbinds := tlv(0x30, varbind)
	pdu := tlv(0xa0, concat( // GetRequest PDU
		berInt(reqID),
		berInt(0), // error-status
		berInt(0), // error-index
		varbinds,
	))
	msg := tlv(0x30, concat(
		berInt(1), // version: 1 == SNMPv2c
		tlv(0x04, []byte(community)),
		pdu,
	))
	return msg, nil
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// ── BER decoding ─────────────────────────────────────────────────────────────

// parseSNMPStringValue walks a GetResponse and returns the first varbind's value
// if it is an OCTET STRING.
func parseSNMPStringValue(b []byte) (string, error) {
	_, msg, _, err := readTLV(b) // outer SEQUENCE content
	if err != nil {
		return "", err
	}
	// version, community, PDU
	_, _, rest, err := readTLV(msg) // version
	if err != nil {
		return "", err
	}
	_, _, rest, err = readTLV(rest) // community
	if err != nil {
		return "", err
	}
	_, pdu, _, err := readTLV(rest) // PDU (0xa2) content
	if err != nil {
		return "", err
	}
	// request-id, error-status, error-index, varbindlist
	_, _, r, err := readTLV(pdu)
	if err != nil {
		return "", err
	}
	_, _, r, err = readTLV(r) // error-status
	if err != nil {
		return "", err
	}
	_, _, r, err = readTLV(r) // error-index
	if err != nil {
		return "", err
	}
	_, vbl, _, err := readTLV(r) // varbindlist content
	if err != nil {
		return "", err
	}
	_, vb, _, err := readTLV(vbl) // first varbind content
	if err != nil {
		return "", err
	}
	_, _, after, err := readTLV(vb) // OID
	if err != nil {
		return "", err
	}
	tag, val, _, err := readTLV(after) // value
	if err != nil {
		return "", err
	}
	if tag != 0x04 { // OCTET STRING
		return "", nil
	}
	return strings.TrimSpace(string(val)), nil
}

// readTLV reads one tag-length-value triple and returns the tag, its content,
// and the remaining bytes after this TLV.
func readTLV(b []byte) (tag byte, content, rest []byte, err error) {
	if len(b) < 2 {
		return 0, nil, nil, errors.New("snmp: truncated TLV")
	}
	tag = b[0]
	n := int(b[1])
	i := 2
	if n&0x80 != 0 { // long-form length
		num := n & 0x7f
		if num == 0 || 2+num > len(b) {
			return 0, nil, nil, errors.New("snmp: bad length")
		}
		n = 0
		for j := 0; j < num; j++ {
			n = n<<8 | int(b[2+j])
		}
		i = 2 + num
	}
	if i+n > len(b) {
		return 0, nil, nil, errors.New("snmp: content exceeds buffer")
	}
	return tag, b[i : i+n], b[i+n:], nil
}
