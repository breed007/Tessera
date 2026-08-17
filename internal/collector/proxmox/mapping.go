package proxmox

import (
	"context"
	"regexp"
	"strings"

	"github.com/breed007/Tessera/internal/observation"
)

const (
	confHostname = 86 // first-party name from the hypervisor
	confClass    = 80
	confOS       = 70
	confBinding  = 82 // a static IP the hypervisor configured
	confVLAN     = 88
)

// node is one PVE node.
type node struct {
	Node string `json:"node"`
}

// guest is a VM or CT list entry.
type guest struct {
	VMID   int    `json:"vmid"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// emit is one observation to record (source is always proxmox).
type emit struct {
	subjectType observation.SubjectType
	subject     string
	attr        observation.Attribute
	value       string
	confidence  int
}

func (c *Client) fetchNodes(ctx context.Context) ([]node, error) {
	var out []node
	return out, c.get(ctx, "/nodes", &out)
}

func (c *Client) fetchGuests(ctx context.Context, nodeName, kind string) ([]guest, error) {
	var out []guest
	return out, c.get(ctx, "/nodes/"+nodeName+"/"+kind, &out)
}

func (c *Client) fetchConfig(ctx context.Context, nodeName, kind string, vmid int) (map[string]any, error) {
	var out map[string]any
	return out, c.get(ctx, "/nodes/"+nodeName+"/"+kind+"/"+itoa(vmid)+"/config", &out)
}

var macRe = regexp.MustCompile(`(?i)\b([0-9a-f]{2}(:[0-9a-f]{2}){5})\b`)

// mapGuest turns one guest's config into observations. kind is "qemu" (VM) or
// "lxc" (CT). Each virtual NIC's MAC is the join key back to the discovered
// device on the wire.
func mapGuest(kind, name string, cfg map[string]any) []emit {
	deviceClass := "Virtual Machine"
	if kind == "lxc" {
		deviceClass = "Container"
	}
	// A CT reports its own hostname in config; prefer it over the list name.
	if h, ok := cfg["hostname"].(string); ok && strings.TrimSpace(h) != "" {
		name = strings.TrimSpace(h)
	}
	os := osFromType(str(cfg["ostype"]))

	var out []emit
	for key, raw := range cfg {
		if !strings.HasPrefix(key, "net") {
			continue
		}
		line, ok := raw.(string)
		if !ok {
			continue
		}
		m := macRe.FindString(line)
		if m == "" {
			continue
		}
		mac := strings.ToLower(m)
		out = append(out,
			emit{observation.SubjectMAC, mac, observation.AttrHostname, name, confHostname},
			emit{observation.SubjectMAC, mac, observation.AttrDeviceClass, deviceClass, confClass},
		)
		if os != "" {
			out = append(out, emit{observation.SubjectMAC, mac, observation.AttrOSGuess, os, confOS})
		}
		// A statically-configured IP (CT ip=10.0.0.5/24). "dhcp"/"manual" have none.
		if ip := ipFromNet(line); ip != "" {
			out = append(out, emit{observation.SubjectMAC, mac, observation.AttrIPBinding, ip, confBinding})
		}
		if tag := kvFromNet(line, "tag"); tag != "" {
			out = append(out, emit{observation.SubjectMAC, mac, observation.AttrVLANMembership, tag, confVLAN})
		}
	}
	return out
}

// ipFromNet pulls a static IPv4/IPv6 from an ip=… field, dropping the prefix
// length. Returns "" for dhcp/manual/absent.
func ipFromNet(line string) string {
	v := kvFromNet(line, "ip")
	if v == "" || v == "dhcp" || v == "manual" || v == "auto" {
		return ""
	}
	if i := strings.IndexByte(v, '/'); i >= 0 {
		v = v[:i]
	}
	return v
}

// kvFromNet returns the value of key in a comma-separated "k=v,k=v" net line.
func kvFromNet(line, key string) string {
	for _, part := range strings.Split(line, ",") {
		if k, v, ok := strings.Cut(part, "="); ok && strings.EqualFold(strings.TrimSpace(k), key) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// osFromType maps a PVE ostype to a readable OS. CT ostypes are distro names;
// VM ostypes are coarse codes (l26, win11, …).
func osFromType(t string) string {
	t = strings.ToLower(strings.TrimSpace(t))
	switch {
	case t == "":
		return ""
	case t == "ubuntu":
		return "Ubuntu"
	case t == "debian":
		return "Debian"
	case t == "alpine":
		return "Alpine Linux"
	case t == "centos":
		return "CentOS"
	case t == "fedora":
		return "Fedora"
	case t == "archlinux":
		return "Arch Linux"
	case t == "opensuse":
		return "openSUSE"
	case t == "gentoo":
		return "Gentoo"
	case t == "nixos":
		return "NixOS"
	case strings.HasPrefix(t, "l2"), strings.HasPrefix(t, "l3"): // l24, l26, l3x
		return "Linux"
	case strings.HasPrefix(t, "win"), strings.HasPrefix(t, "w2k"), t == "wxp", t == "wvista":
		return "Windows"
	case t == "solaris":
		return "Solaris"
	}
	return ""
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func itoa(n int) string {
	// small positive ints only (vmids)
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
