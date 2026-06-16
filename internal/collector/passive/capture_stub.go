//go:build !pcap

package passive

// openCapture in the default build has no libpcap dependency and cannot capture.
// The sensor handles this by logging and idling, so a pure-Go binary still runs
// the rest of Tessera; capture-enabled deployments build with -tags pcap.
func openCapture(_ CaptureConfig) (captureHandle, error) {
	return nil, ErrNoPcap
}
