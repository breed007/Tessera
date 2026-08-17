package proxmox

import (
	"testing"

	"github.com/breed007/Tessera/internal/observation"
)

func find(es []emit, attr observation.Attribute, subject string) *emit {
	for i := range es {
		if es[i].attr == attr && es[i].subject == subject {
			return &es[i]
		}
	}
	return nil
}

func TestMapGuestVM(t *testing.T) {
	// A QEMU VM: MAC lives as the value of the NIC model key, plus a VLAN tag.
	cfg := map[string]any{
		"net0":   "virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,tag=10",
		"ostype": "l26",
	}
	es := mapGuest("qemu", "webserver", cfg)
	if e := find(es, observation.AttrHostname, "bc:24:11:aa:bb:cc"); e == nil || e.value != "webserver" {
		t.Errorf("hostname emit = %+v, want webserver", e)
	}
	if e := find(es, observation.AttrDeviceClass, "bc:24:11:aa:bb:cc"); e == nil || e.value != "Virtual Machine" {
		t.Errorf("class emit = %+v, want Virtual Machine", e)
	}
	if e := find(es, observation.AttrOSGuess, "bc:24:11:aa:bb:cc"); e == nil || e.value != "Linux" {
		t.Errorf("os emit = %+v, want Linux", e)
	}
	if e := find(es, observation.AttrVLANMembership, "bc:24:11:aa:bb:cc"); e == nil || e.value != "10" {
		t.Errorf("vlan emit = %+v, want 10", e)
	}
}

func TestMapGuestCT(t *testing.T) {
	// An LXC container: MAC via hwaddr=, a static IP, distro ostype, own hostname.
	cfg := map[string]any{
		"net0":     "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:11:22,ip=10.0.0.5/24,type=veth",
		"ostype":   "ubuntu",
		"hostname": "pihole",
	}
	es := mapGuest("lxc", "ignored-list-name", cfg)
	const mac = "bc:24:11:00:11:22"
	if e := find(es, observation.AttrHostname, mac); e == nil || e.value != "pihole" {
		t.Errorf("hostname emit = %+v, want pihole (from config)", e)
	}
	if e := find(es, observation.AttrDeviceClass, mac); e == nil || e.value != "Container" {
		t.Errorf("class emit = %+v, want Container", e)
	}
	if e := find(es, observation.AttrOSGuess, mac); e == nil || e.value != "Ubuntu" {
		t.Errorf("os emit = %+v, want Ubuntu", e)
	}
	if e := find(es, observation.AttrIPBinding, mac); e == nil || e.value != "10.0.0.5" {
		t.Errorf("ip emit = %+v, want 10.0.0.5 (prefix stripped)", e)
	}
}

func TestMapGuestDHCPNoIP(t *testing.T) {
	cfg := map[string]any{"net0": "name=eth0,hwaddr=aa:bb:cc:dd:ee:ff,ip=dhcp,bridge=vmbr0"}
	es := mapGuest("lxc", "box", cfg)
	if e := find(es, observation.AttrIPBinding, "aa:bb:cc:dd:ee:ff"); e != nil {
		t.Errorf("dhcp should not emit an ip_binding, got %+v", e)
	}
}
