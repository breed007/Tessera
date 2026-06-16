package reconcile

import "testing"

func TestInferIdentity(t *testing.T) {
	tests := []struct {
		name      string
		in        inferInput
		wantDev   string
		wantOS    string
		minDevCnf int  // 0 = don't care
		allowHigh bool // case is expected to reach the high (≥70) band
	}{
		{
			name:      "printer by port",
			in:        inferInput{openPorts: []int{9100, 80}},
			wantDev:   "printer",
			minDevCnf: 40, // weight-2, single category → medium band
		},
		{
			name:    "windows box by SMB+RDP",
			in:      inferInput{openPorts: []int{445, 139, 3389}},
			wantOS:  "Windows",
			wantDev: "computer",
		},
		{
			name:      "raspberry pi by vendor",
			in:        inferInput{vendor: "Raspberry Pi Foundation"},
			wantDev:   "single-board computer",
			wantOS:    "Linux",
			minDevCnf: 40,
		},
		{
			name:    "iphone by hostname",
			in:      inferInput{hostname: "Bobs-iPhone"},
			wantDev: "Apple mobile device",
			wantOS:  "iOS",
		},
		{
			name:      "camera by vendor agrees with port",
			in:        inferInput{vendor: "Hikvision Digital", openPorts: []int{554}},
			wantDev:   "camera",
			minDevCnf: 60, // two independent categories → medium-high
		},
		{
			name: "no signal yields nothing",
			in:   inferInput{},
		},

		// ── regressions from the inventory screenshots ───────────────────────
		{
			name:      "apple tv by vendor + spaced hostname",
			in:        inferInput{vendor: "Apple, Inc.", hostname: "Apple TV 4K Den"},
			wantDev:   "media / TV device",
			wantOS:    "tvOS",
			minDevCnf: 70, // vendor + hostname agree → high
			allowHigh: true,
		},
		{
			name:      "ring floodlight by vendor + spaced hostname",
			in:        inferInput{vendor: "Ring LLC", hostname: "Ring Floodlight Pro Backyard Right"},
			wantDev:   "camera",
			minDevCnf: 60,
		},
		{
			name:      "esp32 by hostname",
			in:        inferInput{hostname: "esp32-node-01"},
			wantDev:   "IoT device",
			minDevCnf: 40,
		},
		{
			name:      "macbook by mbp hostname + apple vendor",
			in:        inferInput{vendor: "Apple, Inc.", hostname: "studiombp14"},
			wantDev:   "computer",
			wantOS:    "macOS",
			minDevCnf: 70, // OUI + hostname agree → high
			allowHigh: true,
		},
		{
			name:    "android by dhcp vendor class",
			in:      inferInput{dhcpVendor: "android-dhcp-13"},
			wantDev: "mobile phone",
			wantOS:  "Android",
		},
		{
			name: "windows high-confidence by three independent signals",
			in: inferInput{
				openPorts:  []int{445},
				dhcpVendor: "MSFT 5.0",
				hostname:   "DESKTOP-7AB12",
			},
			wantOS:    "Windows",
			wantDev:   "computer",
			minDevCnf: 70,
			allowHigh: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inferIdentity(tt.in)
			if got.deviceClass != tt.wantDev {
				t.Errorf("deviceClass = %q, want %q", got.deviceClass, tt.wantDev)
			}
			if got.osGuess != tt.wantOS {
				t.Errorf("osGuess = %q, want %q", got.osGuess, tt.wantOS)
			}
			if tt.minDevCnf > 0 && got.deviceConf < tt.minDevCnf {
				t.Errorf("deviceConf = %d, want >= %d", got.deviceConf, tt.minDevCnf)
			}
			// Without genuine multi-signal corroboration, inference stays below the
			// high band (≥70). It only ever reaches high when ≥3 independent signal
			// categories agree — and even then it only fills gaps, so an
			// authoritative collector is never overridden.
			if !tt.allowHigh && (got.deviceConf >= 70 || got.osConf >= 70) {
				t.Errorf("inference reached high band without corroboration: dev=%d os=%d", got.deviceConf, got.osConf)
			}
		})
	}
}
