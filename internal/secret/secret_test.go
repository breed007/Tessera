package secret

import "testing"

func TestSealOpenRoundTrip(t *testing.T) {
	c, err := New(GenerateKey())
	if err != nil {
		t.Fatal(err)
	}
	if !c.Enabled() {
		t.Fatal("should be enabled")
	}
	for _, plain := range []string{"hunter2", "a-unifi-password!@#", ""} {
		enc, err := c.Seal(plain)
		if err != nil {
			t.Fatalf("seal %q: %v", plain, err)
		}
		got, err := c.Open(enc)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if got != plain {
			t.Errorf("round-trip: got %q want %q", got, plain)
		}
	}
}

func TestWrongKeyFails(t *testing.T) {
	a, _ := New(GenerateKey())
	b, _ := New(GenerateKey())
	enc, _ := a.Seal("secret")
	if _, err := b.Open(enc); err == nil {
		t.Error("decrypt with the wrong key should fail")
	}
}

func TestDisabledCipher(t *testing.T) {
	c, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	if c.Enabled() {
		t.Error("empty key should be disabled")
	}
	if _, err := c.Seal("x"); err == nil {
		t.Error("seal without a key should error")
	}
}

func TestBadKey(t *testing.T) {
	if _, err := New("too-short"); err == nil {
		t.Error("short/invalid key should error")
	}
}
