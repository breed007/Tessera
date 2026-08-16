package active

import "strings"

// Linux distribution and release from an SSH banner (ported from IP Recon 1.5).
//
// Tessera already grabs this banner and already reduces it, in the inference
// layer, to the single word "Linux" — throwing away a release the server stated
// outright. Debian stamps its own release into the OpenSSH package version:
//
//	SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4   → Debian 13
//
// WHAT IS DELIBERATELY NOT INFERRED. RHEL, CentOS, Rocky and Alma strip the
// distribution marker entirely; nothing here guesses at them. Ubuntu names the
// distribution but not the release, and is recovered only through a table of
// confirmed OpenSSH versions — see ubuntuOpenSSHReleases for the one version
// that is deliberately absent from it.
//
// Appliances need no special guard. A camera or a speaker runs BusyBox or
// dropbear and never emits a Debian marker, and because Tessera contests
// device_class separately from os_guess, "camera" and "Debian Linux 12" can both
// be true of one host without either displacing the other.

// sshDistro is what a banner stated, with a confidence per field: a distribution
// the banner NAMES is a reading, while a release recovered from an OpenSSH
// version is an inference, and the two must not carry the same weight.
type sshDistro struct {
	name        string
	nameConf    int
	version     string
	versionConf int
}

// Confidences. A named distribution is the server's own statement. An explicit
// +debNN release is equally explicit. An Ubuntu release inferred from the
// OpenSSH version is a step down — right whenever the table is right, and the
// table is a maintenance burden that will eventually lag a release.
const (
	confSSHDistro        = 80
	confSSHReleaseStated = 80
	confSSHReleaseInfer  = 62
	// Microsoft's OpenSSH port proves Windows but says nothing reliable about
	// which release — the SSH package updates independently of the OS.
	confSSHWindows = 70
)

// ubuntuOpenSSHReleases maps an upstream OpenSSH version to the Ubuntu release
// that shipped it. Ubuntu's banner ("OpenSSH_9.6p1 Ubuntu-3ubuntu13.18") names
// the distribution and then gives a package revision that says nothing about the
// release, so this is the only way back to one.
//
// Built to fail safe. Only versions confirmed against a shipped release are
// listed, so a NEW Ubuntu reports no version rather than borrowing its nearest
// neighbour's. And 9.0p1 is ABSENT ON PURPOSE: both 22.10 and 23.04 shipped it,
// and a coin flip between two releases is exactly the wrong thing to put in an
// inventory.
var ubuntuOpenSSHReleases = map[string]string{
	"7.2p2": "16.04", "7.6p1": "18.04", "8.2p1": "20.04",
	"8.9p1": "22.04",
	// "9.0p1" omitted on purpose — 22.10 AND 23.04 both shipped it.
	"9.3p1": "23.10", "9.6p1": "24.04", "9.7p1": "24.10", "9.9p1": "25.04",
}

// distroFromSSHBanner reads what the banner states. Returns nil for a banner
// that names nothing — the overwhelming majority, and not a failure.
func distroFromSSHBanner(banner string) *sshDistro {
	if !strings.HasPrefix(banner, "SSH-") {
		return nil
	}
	lower := strings.ToLower(banner)

	// Microsoft's port stamps the literal "_for_Windows_" infix; no Linux or
	// macOS build of OpenSSH ever does.
	if strings.Contains(lower, "openssh_for_windows") {
		return &sshDistro{name: "Windows", nameConf: confSSHWindows}
	}

	switch {
	case strings.Contains(lower, "raspbian"):
		// Checked before Debian: a Raspberry Pi OS banner carries BOTH markers,
		// and the specific one is the useful one. The release still comes from
		// the +debNN stamp, which Raspbian inherits.
		return &sshDistro{
			name: "Raspberry Pi OS", nameConf: confSSHDistro,
			version: debianRelease(banner), versionConf: confSSHReleaseStated,
		}
	case strings.Contains(lower, "debian"):
		return &sshDistro{
			name: "Debian Linux", nameConf: confSSHDistro,
			version: debianRelease(banner), versionConf: confSSHReleaseStated,
		}
	case strings.Contains(lower, "ubuntu"):
		return &sshDistro{
			name: "Ubuntu Linux", nameConf: confSSHDistro,
			version: ubuntuOpenSSHReleases[opensshVersion(banner)], versionConf: confSSHReleaseInfer,
		}
	}
	return nil
}

// debianRelease extracts the release from the `+debNN` marker.
//
//	SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4 → "13"
//
// The bounds are a sanity check, not decoration: they reject a stray "+deb" run
// that is not a release number at all.
func debianRelease(banner string) string {
	i := strings.Index(banner, "+deb")
	if i < 0 {
		return ""
	}
	rest := banner[i+len("+deb"):]
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	if end == 0 || end > 2 {
		return ""
	}
	n := 0
	for _, c := range rest[:end] {
		n = n*10 + int(c-'0')
	}
	if n < 6 || n > 30 {
		return ""
	}
	return rest[:end]
}

// opensshVersion returns the upstream version token from a banner:
// "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.18" → "9.6p1".
func opensshVersion(banner string) string {
	i := strings.Index(banner, "OpenSSH_")
	if i < 0 {
		return ""
	}
	rest := banner[i+len("OpenSSH_"):]
	if j := strings.IndexAny(rest, " \t\r\n"); j >= 0 {
		rest = rest[:j]
	}
	return rest
}
