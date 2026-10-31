package main

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/redis/go-redis/v9"
)

var errIsolationRedisUnavailable = errors.New("injected Redis command failure")

type isolationRedisFault struct{ failed atomic.Bool }

func (f *isolationRedisFault) DialHook(next redis.DialHook) redis.DialHook { return next }

func (f *isolationRedisFault) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if f.failed.Load() {
			cmd.SetErr(errIsolationRedisUnavailable)
			return errIsolationRedisUnavailable
		}
		return next(ctx, cmd)
	}
}

func (f *isolationRedisFault) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		if f.failed.Load() {
			for _, cmd := range cmds {
				cmd.SetErr(errIsolationRedisUnavailable)
			}
			return errIsolationRedisUnavailable
		}
		return next(ctx, cmds)
	}
}
