package replay

import (
	"context"

	"tgen/internal/ratelimit"
)

// rateLimiter aliases ratelimit.Limiter so replayer.go and tests compile unchanged.
type rateLimiter = ratelimit.Limiter

func newRateLimiter(ctx context.Context, rateStr, rampStr string) (*rateLimiter, error) {
	return ratelimit.New(ctx, rateStr, rampStr)
}

// parseRate is retained for TestRateLimiterBPS.
func parseRate(s string) (interface{}, error) {
	return nil, ratelimit.ParseRate(s)
}
