package collector

import (
	"errors"
	"testing"
)

func TestHealthTransitions(t *testing.T) {
	var r Reporter = NewHealth("unifi", "not polled yet") // also asserts Health satisfies Reporter
	h := r.(*Health)

	if st := h.Status(); st.State != "idle" || st.Name != "unifi" || st.Detail != "not polled yet" {
		t.Fatalf("initial = %+v, want idle/unifi", st)
	}

	h.Success("polled — 12 observations")
	st := h.Status()
	if st.State != "ok" || st.Detail != "polled — 12 observations" || st.LastRun.IsZero() {
		t.Errorf("after success = %+v", st)
	}
	if st.Err != "" {
		t.Errorf("success should clear err, got %q", st.Err)
	}

	h.Failure(errors.New("dial tcp: connection refused"))
	st = h.Status()
	if st.State != "error" || st.Err != "dial tcp: connection refused" {
		t.Errorf("after failure = %+v", st)
	}
	if st.Detail != "" {
		t.Errorf("failure should clear detail, got %q", st.Detail)
	}
}
