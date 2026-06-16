package active

import (
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/tessera/tessera/internal/netid"
)

func readProcNetARP() (string, error) {
	b, err := os.ReadFile("/proc/net/arp")
	return string(b), err
}

// arpTable returns the kernel's current IP→MAC table (normalized). After the
// prober has touched a local-subnet host (ICMP/TCP), the kernel resolves and
// caches its MAC; harvesting the cache gives us the L2 binding without ever
// sending a raw ARP frame ourselves (§4.2: read-only, no raw sockets). This
// mirrors IP Recon's ARPResolver approach (read the table, don't raw-send).
func arpTable() map[string]string {
	switch runtime.GOOS {
	case "linux":
		data, err := readProcNetARP()
		if err != nil {
			return nil
		}
		return parseProcNetARP(data)
	default:
		// macOS/BSD: no /proc; parse `arp -an` (read-only).
		out, err := exec.Command("arp", "-an").Output()
		if err != nil {
			return nil
		}
		return parseArpDashA(string(out))
	}
}

// parseProcNetARP parses Linux /proc/net/arp:
//
//	IP address       HW type     Flags       HW address            Mask     Device
//	10.0.0.1         0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
func parseProcNetARP(data string) map[string]string {
	out := map[string]string{}
	lines := strings.Split(data, "\n")
	for i, line := range lines {
		if i == 0 { // header
			continue
		}
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		ip, _, err := netid.NormalizeIP(f[0])
		if err != nil {
			continue
		}
		mac, err := netid.NormalizeMAC(f[3])
		if err != nil || mac == "00:00:00:00:00:00" {
			continue
		}
		out[ip] = mac
	}
	return out
}

// parseArpDashA parses BSD/macOS `arp -an` output:
//
//	? (10.0.0.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
//	? (10.0.0.2) at (incomplete) on en0 ...
func parseArpDashA(data string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		// need: "(<ip>)" ... "at" "<mac>"
		var ip, mac string
		for i, tok := range f {
			if strings.HasPrefix(tok, "(") && strings.HasSuffix(tok, ")") {
				ip = strings.Trim(tok, "()")
			}
			if tok == "at" && i+1 < len(f) {
				mac = f[i+1]
			}
		}
		if ip == "" || mac == "" || mac == "(incomplete)" {
			continue
		}
		nip, _, err := netid.NormalizeIP(ip)
		if err != nil {
			continue
		}
		nmac, err := netid.NormalizeMAC(mac)
		if err != nil {
			continue
		}
		out[nip] = nmac
	}
	return out
}
