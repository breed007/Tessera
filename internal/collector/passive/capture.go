package passive

import (
	"errors"
	"time"
)

// CaptureConfig configures one live capture source (§4.1). Kind is informational
// (a normal "interface" vs a "span" destination); both capture in promiscuous
// mode — the difference is the vantage point, set by how the NIC is cabled.
type CaptureConfig struct {
	Kind        string // "interface" | "span"
	NIC         string
	BPF         string // kernel capture filter; empty → DefaultBPF
	SnapLen     int32
	Promiscuous bool
}

// DefaultBPF restricts a busy SPAN firehose to just the discovery protocols
// Tessera parses, so they reach userspace and nothing else does (§4.1). Applied
// when a source sets no BPF of its own.
const DefaultBPF = "arp or (udp port 67 or 68 or 546 or 547) or (udp port 5353) or (udp port 1900) or (udp port 137) or icmp6"

// ErrNoPcap reports that this binary was built without libpcap capture support.
// Live capture requires building with -tags pcap (and libpcap present); the
// pure-Go default build can parse and reconcile but cannot capture.
var ErrNoPcap = errors.New("passive sensor: built without capture support; rebuild with -tags pcap (requires libpcap)")

// capturedPacket is one raw frame and its capture timestamp.
type capturedPacket struct {
	data []byte
	ts   time.Time
}

// captureHandle is a live capture source. next blocks until the next frame and
// returns a non-nil error once the handle is closed. openCapture, which builds
// one, is defined per build tag in capture_pcap.go / capture_stub.go.
type captureHandle interface {
	next() (capturedPacket, error)
	Close() error
}
