package netid

import "testing"

func TestNormalizeMAC(t *testing.T) {
	cases := map[string]string{
		"B8:27:EB:11:22:33": "b8:27:eb:11:22:33",
		"b8-27-eb-11-22-33": "b8:27:eb:11:22:33",
		"b827.eb11.2233":    "b8:27:eb:11:22:33",
	}
	for in, want := range cases {
		got, err := NormalizeMAC(in)
		if err != nil {
			t.Fatalf("NormalizeMAC(%q) error: %v", in, err)
		}
		if got != want {
			t.Errorf("NormalizeMAC(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := NormalizeMAC("not-a-mac"); err == nil {
		t.Error("expected error for invalid MAC")
	}
}

func TestIsLocallyAdministered(t *testing.T) {
	// U/L bit (bit 1 of first octet) set → randomized.
	if !IsLocallyAdministered("aa:bb:cc:dd:ee:ff") { // 0xaa = 1010 1010, bit1 set
		t.Error("aa:.. should be locally administered")
	}
	// Globally unique OUI (Raspberry Pi) → not randomized.
	if IsLocallyAdministered("b8:27:eb:11:22:33") { // 0xb8 = 1011 1000, bit1 clear
		t.Error("b8:27:eb:.. should NOT be locally administered")
	}
}

func TestNormalizeIP(t *testing.T) {
	ip, ver, err := NormalizeIP("10.0.0.20")
	if err != nil || ip != "10.0.0.20" || ver != 4 {
		t.Fatalf("got %q v%d err=%v", ip, ver, err)
	}
	ip6, ver6, err := NormalizeIP("2001:DB8::1")
	if err != nil || ip6 != "2001:db8::1" || ver6 != 6 {
		t.Fatalf("got %q v%d err=%v", ip6, ver6, err)
	}
	// IPv4-mapped IPv6 collapses to plain IPv4.
	ip4, ver4, _ := NormalizeIP("::ffff:192.168.1.1")
	if ip4 != "192.168.1.1" || ver4 != 4 {
		t.Errorf("mapped addr: got %q v%d", ip4, ver4)
	}
}
