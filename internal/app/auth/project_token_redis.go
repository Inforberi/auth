package auth

import (
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

// NewProjectTokenRedis creates one process-owned pool; share it across projects and close after drain.
func NewProjectTokenRedis(base *redis.Client) (*redis.Client, error) {
	if base == nil {
		return nil, authjwt.ErrConfiguration
	}
	opts := *base.Options()
	opts.MaxRetries, opts.ContextTimeoutEnabled = -1, true
	opts.PoolSize, opts.MaxActiveConns, opts.MinIdleConns, opts.MaxIdleConns = 8, 8, 0, 8
	opts.PoolTimeout, opts.DialTimeout, opts.ReadTimeout, opts.WriteTimeout = time.Second, time.Second, time.Second, time.Second
	return redis.NewClient(&opts), nil
}

func validProjectTokenRedis(client *redis.Client) bool {
	opts := client.Options()
	if opts.MaxRetries != 0 || !opts.ContextTimeoutEnabled || opts.MinIdleConns != 0 {
		return false
	}
	for _, limit := range []int{opts.PoolSize, opts.MaxActiveConns, opts.MaxIdleConns} {
		if limit < 1 || limit > 8 {
			return false
		}
	}
	for _, timeout := range []time.Duration{opts.PoolTimeout, opts.DialTimeout, opts.ReadTimeout, opts.WriteTimeout} {
		if timeout <= 0 || timeout > time.Second {
			return false
		}
	}
	return true
}
