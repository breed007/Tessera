package fingerbank

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// TestKey verifies a Fingerbank API key (§M10 settings test) by interrogating a
// well-known fingerprint. A nil error means the key is accepted and not rate
// limited. NOTE: this makes one real request to Fingerbank.
func TestKey(ctx context.Context, key string) error {
	if key == "" {
		return errors.New("API key is empty")
	}
	c := &client{http: &http.Client{Timeout: 12 * time.Second}, endpoint: defaultEndpoint, key: key}
	_, err := c.interrogate(ctx, Signature{
		DHCPFingerprint: "1,3,6,15,28,51,58,59", // a common Android/Linux fingerprint
		MAC:             "00:00:00:00:00:00",
	})
	if errors.Is(err, errRateLimited) {
		return errors.New("rate limited — key works but you're at the hourly limit")
	}
	return err
}
