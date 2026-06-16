package unifi

import "testing"

func TestNormalizeBaseURL(t *testing.T) {
	cases := map[string]string{
		"192.168.10.1":          "https://192.168.10.1",
		"192.168.10.1/":         "https://192.168.10.1",
		" 192.168.1.1 ":         "https://192.168.1.1",
		"https://10.0.0.1":      "https://10.0.0.1",
		"http://10.0.0.1:8443/": "http://10.0.0.1:8443",
		"https://udm.local/":    "https://udm.local",
		"":                      "",
	}
	for in, want := range cases {
		if got := normalizeBaseURL(in); got != want {
			t.Errorf("normalizeBaseURL(%q) = %q, want %q", in, got, want)
		}
	}
}
