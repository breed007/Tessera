package oui

import "testing"

func TestLookup(t *testing.T) {
	if v, ok := Lookup("b8:27:eb:11:22:33"); !ok || v != "Raspberry Pi Foundation" {
		t.Errorf("Pi lookup = %q,%v", v, ok)
	}
	if v, ok := Lookup("f0:9f:c2:aa:bb:cc"); !ok || v != "Ubiquiti Networks" {
		t.Errorf("Ubiquiti lookup = %q,%v", v, ok)
	}
	// Randomized (locally-administered) MAC → never a vendor (§6).
	if _, ok := Lookup("aa:bb:cc:dd:ee:ff"); ok {
		t.Error("randomized MAC should not resolve a vendor")
	}
	// Unknown prefix.
	if _, ok := Lookup("12:34:56:78:9a:bc"); ok {
		t.Error("unknown prefix should not resolve")
	}
}
