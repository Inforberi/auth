package service

import (
	"context"
	"time"
)

type Tokens interface {
	GenerateToken(...int) (string, error)
	Hash(string) string
}

type Check func(encrypted []byte, lastStep int64, now time.Time) (int64, error)

type Cipher interface {
	Seal([]byte) ([]byte, error)
	Open([]byte) ([]byte, error)
	Digest(string) string
}

type Authenticator interface {
	Generate(string, string) (string, string, error)
	Match(string, string, time.Time, int64) (int64, error)
}

type Limiter interface {
	Allow(context.Context, string, int, time.Duration) (bool, error)
	AllowAll(context.Context, []Budget) (bool, error)
}

type Budget struct {
	Key   string
	Count int
}
