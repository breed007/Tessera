package active

import "testing"

// Every case here is a build string measured off a real device (see
// applebuild.go), plus the refusals that keep a wrong version out of a report.
func TestAppleOSVersion(t *testing.T) {
	cases := []struct {
		name                   string
		model, osVer, buildVer string
		want                   string
	}{
		// The measurement that motivated this: a Mac states only a build.
		{"mac build", "Mac16,8", "", "25G76", "26.6"},
		{"macbook build", "MacBookPro18,3", "", "24C101", "15.2"},
		{"imac build", "iMac21,1", "", "23A344", "14.0"},
		// Apple TV: looked up, never computed. Arithmetic would give "26.11".
		{"apple tv exact build", "AppleTV11,1", "", "23L773", "26.6"},
		{"apple tv unlisted build falls back to the major", "AppleTV14,1", "", "22J364", "18"},
		// iPhone/iPad state the version outright; it wins over any derivation.
		{"stated version wins", "iPhone15,2", "18.3.1", "22D72", "18.3.1"},
		// Refusals.
		{"unmapped darwin major yields nothing", "Mac99,1", "", "40A1", ""},
		{"unmapped tv series yields nothing", "AppleTV11,1", "", "30A1", ""},
		{"an iOS build is never run through the macOS table", "iPhone15,2", "", "22D72", ""},
		{"no build and no version", "Mac16,8", "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := appleOSVersion(c.model, c.osVer, c.buildVer); got != c.want {
				t.Errorf("appleOSVersion(%q,%q,%q) = %q, want %q", c.model, c.osVer, c.buildVer, got, c.want)
			}
		})
	}
}

// A tvOS build must not be readable as a macOS version and vice versa — the two
// series numbers overlap in range, so only the model gate separates them.
func TestAppleBuildTablesAreNotInterchangeable(t *testing.T) {
	if v := macOSVersion("23L773", "AppleTV11,1"); v != "" {
		t.Errorf("macOSVersion accepted a tvOS build/model: %q", v)
	}
	if v := tvOSVersion("25G76", "Mac16,8"); v != "" {
		t.Errorf("tvOSVersion accepted a Mac build/model: %q", v)
	}
}
