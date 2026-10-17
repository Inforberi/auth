package service

import (
	"time"

	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type NativePolicy struct {
	IdleTTL, AbsoluteTTL time.Duration
	Sessions             sessionservice.Config
}

func (p NativePolicy) Validate() error {
	if p.IdleTTL < time.Minute || p.AbsoluteTTL < p.IdleTTL || p.IdleTTL > p.Sessions.SessionTTL || p.AbsoluteTTL > p.Sessions.AbsoluteSessionTTL ||
		p.Sessions.AdminIdleTimeout < time.Minute || p.Sessions.AdminActivityInterval < time.Second ||
		p.Sessions.AdminActivityInterval > p.Sessions.AdminIdleTimeout/10 || p.Sessions.AdminAbsoluteTTL < p.Sessions.AdminIdleTimeout {
		return authjwt.ErrConfiguration
	}
	for _, d := range []time.Duration{p.IdleTTL, p.AbsoluteTTL, p.Sessions.AdminIdleTimeout, p.Sessions.AdminActivityInterval, p.Sessions.AdminAbsoluteTTL} {
		if d%time.Second != 0 {
			return authjwt.ErrConfiguration
		}
	}
	return nil
}
