package service

import (
	"context"
	"time"
)

type Limiter interface {
	Allow(context.Context, string, int, time.Duration) (bool, error)
}

type Cipher interface {
	Seal([]byte) ([]byte, error)
	Open([]byte) ([]byte, error)
	Digest(string) string
}

type Mailer interface {
	SendContext(context.Context, string, string, string) error
}
