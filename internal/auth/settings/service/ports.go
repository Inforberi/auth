package service

import (
	"context"
	"time"
)

type ProviderCipher interface {
	Seal([]byte) ([]byte, error)
	Open([]byte) ([]byte, error)
}

type SettingsLimiter interface {
	Allow(context.Context, string, int, time.Duration) (bool, error)
}
