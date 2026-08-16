package active

import "testing"

// The shape of the real 2,828-byte login page, reduced to what is parsed.
const pveLoginPage = `<html><head><title>pve1 - Proxmox Virtual Environment</title>
<script type="text/javascript" src="/pve2/js/pvemanagerlib.js?ver=9.2.5"></script>
</head><body></body></html>`

func TestParseProxmoxPage(t *testing.T) {
	f := parseProxmoxPage(pveLoginPage)
	if f == nil {
		t.Fatal("the real page shape did not parse")
	}
	if f.version != "9.2.5" {
		t.Errorf("version = %q, want 9.2.5", f.version)
	}
	if f.nodeName != "pve1" {
		t.Errorf("nodeName = %q, want pve1", f.nodeName)
	}
}

// Identity is the gate: anything can listen on 8006, and a port number is not a
// hypervisor.
func TestProxmoxRequiresPositiveIdentity(t *testing.T) {
	pages := []string{
		"",
		"<html><title>some other app - Console</title></html>",
		// Right port, right-looking bundle, wrong product.
		`<html><title>x - y</title><script src="/pve2/js/pvemanagerlib.js?ver=9.2.5"></script></html>`,
	}
	for _, p := range pages {
		if f := parseProxmoxPage(p); f != nil {
			t.Errorf("page without the product name identified as Proxmox: %+v", f)
		}
	}
}

// A version must be at least major.minor. A truncated read is not a version.
func TestProxmoxVersionRejectsPartialReads(t *testing.T) {
	cases := map[string]string{
		`pvemanagerlib.js?ver=9.2.5"`: "9.2.5",
		`pvemanagerlib.js?ver=8.1"`:   "8.1",
		`pvemanagerlib.js?ver=9"`:     "", // bare major
		`pvemanagerlib.js?ver=9."`:    "", // trailing dot
		`pvemanagerlib.js?ver="`:      "",
		`no bundle here`:              "",
	}
	for body, want := range cases {
		if got := proxmoxVersion(body); got != want {
			t.Errorf("proxmoxVersion(%q) = %q, want %q", body, got, want)
		}
	}
}

// The node name is the part of the title before " - "; a title without that
// separator yields nothing rather than the whole string.
func TestProxmoxNode(t *testing.T) {
	cases := map[string]string{
		"<title>pve1 - Proxmox Virtual Environment</title>": "pve1",
		"<title>Proxmox Virtual Environment</title>":        "",
		"<title></title>": "",
		"no title":        "",
	}
	for body, want := range cases {
		if got := proxmoxNode(body); got != want {
			t.Errorf("proxmoxNode(%q) = %q, want %q", body, got, want)
		}
	}
}
