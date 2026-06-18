package portrisk

import "testing"

func TestClassify(t *testing.T) {
	cases := map[int]string{23: "high", 3306: "medium", 80: "low", 5901: "high", 513: "medium"}
	for port, sev := range cases {
		r, ok := Classify(port)
		if !ok || r.Severity != sev {
			t.Errorf("Classify(%d) = %+v,%v want severity %q", port, r, ok, sev)
		}
	}
	for _, normal := range []int{22, 443, 53} {
		if _, ok := Classify(normal); ok {
			t.Errorf("port %d should not be flagged", normal)
		}
	}
}
