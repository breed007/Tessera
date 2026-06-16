package icons

import "testing"

func TestAuto(t *testing.T) {
	cases := []struct{ vendor, os, dc, want string }{
		{"Ubiquiti Networks", "", "UniFi Switch", "ubiquiti"},
		{"Raspberry Pi Foundation", "", "Single-Board Computer", "raspberrypi"},
		{"", "Windows 10", "", "microsoft"},
		{"", "Linux 5.10", "", "linux"},
		{"Apple", "", "", "apple"},
		{"", "", "NAS", "nas"},
		{"", "", "IP Camera", "camera"},
		{"Unknown Vendor", "", "", "unknown"},
	}
	for _, c := range cases {
		if got := Auto(c.vendor, c.os, c.dc); got != c.want {
			t.Errorf("Auto(%q,%q,%q) = %q, want %q", c.vendor, c.os, c.dc, got, c.want)
		}
	}
}
