package fingerbank

import (
	"context"
	"errors"
	"math/rand"
	"net/http"
	"time"
)

// apiEnricher classifies via the Fingerbank API, fronted by the §7 governor and
// signature cache. The cache collapses identical combinations to one lifetime
// lookup; the governor keeps us under the rate ceiling and backs off on 429.
type apiEnricher struct {
	client *client
	gov    *governor
	cache  *cache
	ttl    time.Duration

	backoffBase time.Duration
	now         func() time.Time
	jitter      func(time.Duration) time.Duration
}

// APIConfig configures the api-mode enricher.
type APIConfig struct {
	Key        string
	Endpoint   string // empty → defaultEndpoint
	MaxPerHour int
	Burst      int
	CacheTTL   time.Duration
	HTTPClient doer // nil → http.Client with a sane timeout
}

// NewAPI builds an api-mode enricher. The key is required and is never logged.
func NewAPI(cfg APIConfig) (Enricher, error) {
	if cfg.Key == "" {
		return nil, errors.New("fingerbank: api mode requires an API key (TESSERA_FINGERBANK_KEY)")
	}
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	ttl := cfg.CacheTTL
	if ttl <= 0 {
		ttl = 720 * time.Hour
	}
	return &apiEnricher{
		client:      &client{http: hc, endpoint: endpoint, key: cfg.Key},
		gov:         newGovernor(cfg.MaxPerHour, cfg.Burst),
		cache:       newCache(ttl),
		ttl:         ttl,
		backoffBase: 5 * time.Minute,
		now:         time.Now,
		jitter:      defaultJitter,
	}, nil
}

func (e *apiEnricher) Mode() string { return "api" }
func (e *apiEnricher) Close() error { return nil }

// Classify returns a cached verdict if present; otherwise it acquires a rate
// token, interrogates, caches the result (positive OR negative), and on a 429
// backs the governor off rather than retrying — the caller simply tries again a
// later cycle.
func (e *apiEnricher) Classify(ctx context.Context, sig Signature) (Verdict, error) {
	key := sig.CacheKey()
	if v, ok := e.cache.get(key, e.now()); ok {
		return v, nil
	}
	if err := e.gov.acquire(ctx); err != nil {
		return Verdict{}, err
	}
	v, err := e.client.interrogate(ctx, sig)
	if err != nil {
		if errors.Is(err, errRateLimited) {
			e.gov.backoff(e.backoffBase + e.jitter(e.backoffBase))
		}
		return Verdict{}, err
	}
	e.cache.put(key, v, e.now())
	return v, nil
}

// defaultJitter returns a random fraction (0–25%) of base, spreading retries.
func defaultJitter(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(base) / 4)) //nolint:gosec // jitter, not security-sensitive
}
