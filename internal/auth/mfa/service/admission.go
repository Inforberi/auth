package service

import (
	"context"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

func AdmitFactorUser(ctx context.Context, cipher Cipher, limit Limiter, operations int, user accountdomain.UserID) error {
	return AdmitBudgets(ctx, limit, []Budget{
		{Key: cipher.Digest("user:" + string(user)), Count: operations},
		{Key: cipher.Digest("login:factor-user:" + string(user)), Count: 5},
	})
}

func AdmitLogin(ctx context.Context, cipher Cipher, limit Limiter, cfg LoginConfig, purpose, subject, ip string, count int) error {
	subjectKey := "login:" + purpose + ":subject:" + cipher.Digest(subject)
	if purpose == "start" {
		subjectKey = cipher.Digest("user:" + subject)
	}
	return AdmitBudgets(ctx, limit, []Budget{
		{Key: subjectKey, Count: count},
		{Key: "login:ip:" + cipher.Digest(ip), Count: cfg.IPLimitPerMinute},
		{Key: "project", Count: cfg.GlobalLimitPerMinute},
	})
}

func AdmitBudgets(ctx context.Context, limit Limiter, budgets []Budget) error {
	allowed, err := limit.AllowAll(ctx, budgets)
	if err != nil {
		return domain.ErrUnavailable
	}
	if !allowed {
		return domain.ErrLimited
	}
	return nil
}
