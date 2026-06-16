package unifi

import "context"

// Test verifies a controller connection (§M10 settings test): it logs in and
// fetches the client list, returning how many clients are visible. A nil error
// means the credentials and URL work.
func Test(ctx context.Context, cfg Config) (int, error) {
	cl, err := New(cfg)
	if err != nil {
		return 0, err
	}
	clients, err := cl.fetchClients(ctx)
	if err != nil {
		return 0, err
	}
	return len(clients), nil
}
