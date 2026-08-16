package active

import (
	"strconv"
	"strings"
)

// Apple OS versions derived from a build string (ported from IP Recon 1.5).
//
// WHY THIS EXISTS — the version was on the wire and we were discarding it.
// probeAirPlay reads `osVersion` from the /info plist, and that key is present
// on iPhones and iPads. It is ABSENT on Macs and Apple TVs, which instead send
// `osBuildVersion`. Measured on 2026-08-14: a Mac on :7000 answered
// `osBuildVersion=25G76, model=Mac16,8` and no `osVersion` at all; two Apple TVs
// answered `osBuildVersion=23L773`. So every Mac and Apple TV Tessera probed
// successfully yielded an OS name with no version, from a body that stated one.
//
// Build strings are `<series><letter><number>`. The series maps to a marketing
// major through a TABLE, never arithmetic: Apple tracked the two for years and
// then jumped macOS 15 → 26 while the series advanced 24 → 25. The letter is
// where the two families diverge, which is why they need separate functions.
//
// Both refuse rather than guess. An unmapped series returns "" so a future
// release reads as bare "macOS" — a missing version is a gap, a wrong one is a
// lie the operator has no way to catch.

// darwinToMacOSMajor maps the Darwin major in a Mac build string to the macOS
// marketing major. macOS builds carry the DARWIN number (macOS 26 = 25x).
var darwinToMacOSMajor = map[int]int{
	20: 11, 21: 12, 22: 13, 23: 14, 24: 15, 25: 26,
}

// buildSeriesToTVOSMajor maps the build series in a tvOS build string to the
// tvOS marketing major. Note this is the iOS-family series (tvOS 26 = 23x), NOT
// the Darwin major macOS uses (macOS 26 = 25x) — running a tvOS build through
// the macOS table is exactly the mistake that made this a separate function.
var buildSeriesToTVOSMajor = map[int]int{
	19: 15, 20: 16, 21: 17, 22: 18, 23: 26,
}

// tvOSBuildToVersion pins exact tvOS builds to their release.
//
// The letter CANNOT be read arithmetically here the way it can for macOS. tvOS
// trains start at J (tvOS 15.0 = 19J346, 16.0 = 20J373, 17.0 = 21J354,
// 18.0 = 22J364) and several point releases share a letter. Read as an offset
// from "A", 23L773 would be "26.11" — not a release that exists.
//
// So exact builds are looked up, and each entry records a device actually read:
//
//	23L773 → tvOS 26.6, confirmed 2026-08-15 on two Apple TVs (AppleTV11,1).
//
// Anything unlisted falls back to the major alone; an unknown series to "".
var tvOSBuildToVersion = map[string]string{
	"23L773": "26.6",
}

// macOSVersion derives a BARE version like "26.6" from a build like "25G76".
//
// Bare on purpose: os_guess already holds "macOS" and the reader composes the
// two. Returning "macOS 26.6" here is how IP Recon ended up rendering
// "macOS macOS 26.5".
//
// The letter is the minor release counted from A — 25**G**76 → Darwin 25,
// minor 6 → macOS 26.6, verified against a Mac reporting 25G76 on macOS 26.6.1.
// Gated on a Mac model so an iOS build string can never be run through this
// table.
func macOSVersion(build, model string) string {
	if build == "" || !isMacModel(model) {
		return ""
	}
	series, rest := splitBuild(build)
	major, ok := darwinToMacOSMajor[series]
	if !ok {
		return ""
	}
	if rest == "" || rest[0] < 'A' || rest[0] > 'Z' {
		return strconv.Itoa(major)
	}
	return strconv.Itoa(major) + "." + strconv.Itoa(int(rest[0]-'A'))
}

// tvOSVersion derives a BARE version like "26.6" from a build like "23L773",
// preferring the exact-build table and falling back to the major alone. Gated on
// an Apple TV model, and returns "" for an unknown series — at which point the
// caller states the OS with no version, which is always true.
func tvOSVersion(build, model string) string {
	if build == "" || !strings.HasPrefix(model, "AppleTV") {
		return ""
	}
	if exact, ok := tvOSBuildToVersion[build]; ok {
		return exact
	}
	series, _ := splitBuild(build)
	if major, ok := buildSeriesToTVOSMajor[series]; ok {
		return strconv.Itoa(major)
	}
	return ""
}

// appleOSVersion picks the right derivation for the model, or passes through an
// osVersion the device stated outright (iPhone and iPad send one; Mac and Apple
// TV do not). A stated version always beats a derived one.
func appleOSVersion(model, osVersion, buildVersion string) string {
	if osVersion != "" {
		return osVersion
	}
	switch {
	case strings.HasPrefix(model, "AppleTV"):
		return tvOSVersion(buildVersion, model)
	case isMacModel(model):
		return macOSVersion(buildVersion, model)
	}
	return ""
}

// isMacModel reports whether an Apple model identifier names a Mac. "Mac16,8",
// "MacBookPro18,3" and "iMac21,1" are all Macs; "iPhone15,2" is not.
func isMacModel(model string) bool {
	return strings.HasPrefix(model, "Mac") || strings.HasPrefix(model, "iMac")
}

// splitBuild splits a build string into its leading series number and the rest
// ("25G76" → 25, "G76"). Returns -1 when the string does not start with digits.
func splitBuild(build string) (series int, rest string) {
	i := 0
	for i < len(build) && build[i] >= '0' && build[i] <= '9' {
		i++
	}
	if i == 0 {
		return -1, build
	}
	n := 0
	for _, c := range build[:i] {
		n = n*10 + int(c-'0')
	}
	return n, build[i:]
}
