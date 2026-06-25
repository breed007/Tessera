package dhcp

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/tessera/tessera/internal/observation"
)

func TestParseLeaseLine(t *testing.T) {
	cases := []struct {
		line             string
		ok               bool
		mac, ip, host    string
	}{
		{"1735689600 aa:bb:cc:dd:ee:ff 10.0.0.5 my-laptop 01:aa:bb:cc:dd:ee:ff", true, "aa:bb:cc:dd:ee:ff", "10.0.0.5", "my-laptop"},
		{"1735689600 AA:BB:CC:11:22:33 10.0.0.6 * *", true, "aa:bb:cc:11:22:33", "10.0.0.6", ""},
		{"duid ...", false, "", "", ""},
		{"", false, "", "", ""},
		{"1735689600 not-a-mac 10.0.0.7 host", false, "", "", ""},
		{"1735689600 aa:bb:cc:dd:ee:ff not-an-ip host", false, "", "", ""},
	}
	for _, c := range cases {
		l, ok := parseLeaseLine(c.line)
		if ok != c.ok {
			t.Errorf("parseLeaseLine(%q) ok=%v, want %v", c.line, ok, c.ok)
			continue
		}
		if ok && (l.MAC != c.mac || l.IP != c.ip || l.Hostname != c.host) {
			t.Errorf("parseLeaseLine(%q) = %+v, want mac=%s ip=%s host=%s", c.line, l, c.mac, c.ip, c.host)
		}
	}
}

type capAppender struct{ obs []observation.Observation }

func (c *capAppender) Append(_ context.Context, o observation.Observation) (int64, error) {
	c.obs = append(c.obs, o)
	return int64(len(c.obs)), nil
}
func (c *capAppender) AppendBatch(ctx context.Context, os []observation.Observation) error {
	for _, o := range os {
		if _, err := c.Append(ctx, o); err != nil {
			return err
		}
	}
	return nil
}

func TestReadAndEmit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsmasq.leases")
	content := "1735689600 aa:bb:cc:dd:ee:ff 10.0.0.5 nas 01:aa\n1735689600 11:22:33:44:55:66 10.0.0.6 * *\n\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cap := &capAppender{}
	sink := observation.NewSink("dhcp", cap)
	c := New(Config{Files: []string{path}})
	c.runOnce(context.Background(), sink)

	has := func(sty observation.SubjectType, subj string, attr observation.Attribute, val string) bool {
		for _, o := range cap.obs {
			if o.SubjectType == sty && o.Subject == subj && o.Attribute == attr && o.Value == val {
				return true
			}
		}
		return false
	}
	if !has(observation.SubjectMAC, "aa:bb:cc:dd:ee:ff", observation.AttrIPBinding, "10.0.0.5") {
		t.Errorf("missing ip_binding for nas; obs=%+v", cap.obs)
	}
	if !has(observation.SubjectMAC, "aa:bb:cc:dd:ee:ff", observation.AttrHostname, "nas") {
		t.Errorf("missing hostname for nas")
	}
	if !has(observation.SubjectIPv4, "10.0.0.5", observation.AttrDHCPLease, "dynamic") {
		t.Errorf("missing dhcp_lease=dynamic for 10.0.0.5")
	}
	// The "*" hostname lease has no hostname observation.
	for _, o := range cap.obs {
		if o.Attribute == observation.AttrHostname && o.Subject == "11:22:33:44:55:66" {
			t.Errorf("'*' hostname should not emit a hostname observation: %+v", o)
		}
	}
	if c.Status().State != "ok" {
		t.Errorf("collector state = %q, want ok", c.Status().State)
	}
}
