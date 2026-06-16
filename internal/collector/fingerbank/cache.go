package fingerbank

import (
	"sync"
	"time"
)

// cache stores verdicts keyed by signature combination (§7: aggressive caching
// and dedup by fingerprint signature, not MAC). Negative results are cached too,
// so an unknown combination isn't re-queried every cycle. Entries expire after
// the configured TTL.
type cache struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]cacheEntry
}

type cacheEntry struct {
	verdict Verdict
	expires time.Time
}

func newCache(ttl time.Duration) *cache {
	if ttl <= 0 {
		ttl = 720 * time.Hour // 30d default (§5)
	}
	return &cache{ttl: ttl, m: make(map[string]cacheEntry)}
}

func (c *cache) get(key string, now time.Time) (Verdict, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok || now.After(e.expires) {
		if ok {
			delete(c.m, key)
		}
		return Verdict{}, false
	}
	return e.verdict, true
}

func (c *cache) put(key string, v Verdict, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[key] = cacheEntry{verdict: v, expires: now.Add(c.ttl)}
}
