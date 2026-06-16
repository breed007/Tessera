//go:build pcap

// This file is the ONLY place libpcap/cgo enters Tessera. It is compiled only
// in builds tagged `pcap` (which require libpcap headers + a C toolchain). The
// parsers and the rest of the daemon stay pure-Go and build without it.
package passive

import (
	"fmt"

	"github.com/gopacket/gopacket/pcap"
)

// openCapture opens a promiscuous live capture on the source NIC and installs a
// kernel BPF filter (§4.1): filtering in the kernel keeps a busy SPAN from
// overwhelming userspace. The capture NIC should be separate from management —
// mirror-destination ports are frequently TX-disabled, which is fine because the
// sensor only reads here.
func openCapture(cfg CaptureConfig) (captureHandle, error) {
	snap := cfg.SnapLen
	if snap <= 0 {
		snap = 65535
	}
	h, err := pcap.OpenLive(cfg.NIC, snap, cfg.Promiscuous, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("pcap: open %s: %w", cfg.NIC, err)
	}
	bpf := cfg.BPF
	if bpf == "" {
		bpf = DefaultBPF
	}
	if err := h.SetBPFFilter(bpf); err != nil {
		h.Close()
		return nil, fmt.Errorf("pcap: set BPF on %s: %w", cfg.NIC, err)
	}
	return &pcapHandle{h: h}, nil
}

type pcapHandle struct {
	h *pcap.Handle
}

func (p *pcapHandle) next() (capturedPacket, error) {
	data, ci, err := p.h.ReadPacketData()
	if err != nil {
		return capturedPacket{}, err
	}
	// ReadPacketData returns a fresh slice per call, safe to retain.
	return capturedPacket{data: data, ts: ci.Timestamp}, nil
}

func (p *pcapHandle) Close() error {
	p.h.Close()
	return nil
}
