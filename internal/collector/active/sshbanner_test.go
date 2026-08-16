package active

import "testing"

func TestDistroFromSSHBanner(t *testing.T) {
	cases := []struct {
		banner            string
		name, version     string
		wantVersionConfLo bool // the release is an inference, not a reading
	}{
		// Debian states its release; this is a reading.
		{"SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4", "Debian Linux", "13", false},
		{"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2", "Debian Linux", "12", false},
		// Raspberry Pi OS carries both markers; the specific one wins.
		{"SSH-2.0-OpenSSH_9.2p1 Raspbian-2+deb12u2", "Raspberry Pi OS", "12", false},
		// Ubuntu names the distro but not the release — inferred, lower confidence.
		{"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.18", "Ubuntu Linux", "24.04", true},
		{"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6", "Ubuntu Linux", "22.04", true},
		// Windows: proves the family, says nothing dependable about the release.
		{"SSH-2.0-OpenSSH_for_Windows_8.6", "Windows", "", false},
		// A Debian banner with no release marker: the name still stands.
		{"SSH-2.0-OpenSSH_9.2p1 Debian", "Debian Linux", "", false},
	}
	for _, c := range cases {
		d := distroFromSSHBanner(c.banner)
		if d == nil {
			t.Errorf("%q did not parse", c.banner)
			continue
		}
		if d.name != c.name || d.version != c.version {
			t.Errorf("%q → %q/%q, want %q/%q", c.banner, d.name, d.version, c.name, c.version)
		}
		if c.version != "" && c.wantVersionConfLo && d.versionConf >= confSSHReleaseStated {
			t.Errorf("%q: an inferred release carries a stated release's confidence (%d)", c.banner, d.versionConf)
		}
	}
}

// The distributions that strip the marker must yield nothing, not a guess.
func TestDistroFromSSHBannerRefusals(t *testing.T) {
	for _, b := range []string{
		"SSH-2.0-OpenSSH_8.7",                  // RHEL/Rocky/Alma — marker stripped
		"SSH-2.0-OpenSSH_9.9 FreeBSD-20250101", // named, but not one we map
		"SSH-2.0-dropbear_2022.83",             // appliance
		"SSH-2.0-Cisco-1.25",
		"220 mail.example.com ESMTP", // not SSH at all
		"",
	} {
		if d := distroFromSSHBanner(b); d != nil {
			t.Errorf("%q produced %+v, want nothing", b, d)
		}
	}
}

// 9.0p1 shipped in BOTH 22.10 and 23.04. Naming either is a coin flip presented
// as a finding, so the table must not contain it.
func TestUbuntuAmbiguousVersionIsNotInferred(t *testing.T) {
	if _, ok := ubuntuOpenSSHReleases["9.0p1"]; ok {
		t.Fatal("9.0p1 is in the table; it is ambiguous between 22.10 and 23.04")
	}
	d := distroFromSSHBanner("SSH-2.0-OpenSSH_9.0p1 Ubuntu-1ubuntu7.1")
	if d == nil || d.name != "Ubuntu Linux" {
		t.Fatalf("expected the distro to still be named, got %+v", d)
	}
	if d.version != "" {
		t.Errorf("version = %q, want none for an ambiguous OpenSSH version", d.version)
	}
}

func TestDebianReleaseBounds(t *testing.T) {
	cases := map[string]string{
		"OpenSSH_10.0p2 Debian-7+deb13u4": "13",
		"OpenSSH_9.2p1 Debian-2+deb9u1":   "9",
		"Debian-1+deb999u1":               "", // too many digits to be a release
		"Debian-1+deb2u1":                 "", // below the plausible range
		"Debian-1+debu1":                  "", // no digits at all
		"OpenSSH_9.2p1 Debian":            "",
	}
	for banner, want := range cases {
		if got := debianRelease(banner); got != want {
			t.Errorf("debianRelease(%q) = %q, want %q", banner, got, want)
		}
	}
}

func TestOpenSSHVersionToken(t *testing.T) {
	cases := map[string]string{
		"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.18": "9.6p1",
		"SSH-2.0-OpenSSH_8.9p1":                     "8.9p1",
		"SSH-2.0-dropbear_2022.83":                  "",
	}
	for banner, want := range cases {
		if got := opensshVersion(banner); got != want {
			t.Errorf("opensshVersion(%q) = %q, want %q", banner, got, want)
		}
	}
}
