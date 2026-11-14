package service

import (
	"errors"
	"time"
)

var ErrInvalidBrowserPolicy = errors.New("invalid browser session policy")

type BrowserPolicy struct {
	IdleSeconds             int64 `json:"idleSeconds"`
	AbsoluteSeconds         int64 `json:"absoluteSeconds"`
	RefreshThresholdSeconds int64 `json:"refreshThresholdSeconds"`
	AdminIdleSeconds        int64 `json:"adminIdleSeconds"`
	AdminAbsoluteSeconds    int64 `json:"adminAbsoluteSeconds"`
	AdminActivitySeconds    int64 `json:"adminActivitySeconds"`
}

func (cfg Config) BrowserPolicy() BrowserPolicy {
	return BrowserPolicy{
		IdleSeconds:             int64(cfg.SessionTTL / time.Second),
		AbsoluteSeconds:         int64(cfg.AbsoluteSessionTTL / time.Second),
		RefreshThresholdSeconds: int64(cfg.SessionRefreshThreshold / time.Second),
		AdminIdleSeconds:        int64(cfg.AdminIdleTimeout / time.Second),
		AdminAbsoluteSeconds:    int64(cfg.AdminAbsoluteTTL / time.Second),
		AdminActivitySeconds:    int64(cfg.AdminActivityInterval / time.Second),
	}
}

func (p BrowserPolicy) Validate(ceiling BrowserPolicy) error {
	if p.RefreshThresholdSeconds < 1 || p.IdleSeconds <= p.RefreshThresholdSeconds ||
		p.AbsoluteSeconds < p.IdleSeconds || p.IdleSeconds > ceiling.IdleSeconds || p.AbsoluteSeconds > ceiling.AbsoluteSeconds {
		return ErrInvalidBrowserPolicy
	}
	if p.AdminIdleSeconds < 60 || p.AdminAbsoluteSeconds < p.AdminIdleSeconds ||
		p.AdminActivitySeconds < 1 || p.AdminActivitySeconds > p.AdminIdleSeconds/10 ||
		p.AdminIdleSeconds > ceiling.AdminIdleSeconds || p.AdminAbsoluteSeconds > ceiling.AdminAbsoluteSeconds {
		return ErrInvalidBrowserPolicy
	}
	return nil
}
