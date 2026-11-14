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
	userLimit, ipLimit, projectLimit, err := cfg.Budget(ctx)
	if err != nil {
		return err
	}
	subjectKey := "login:" + purpose + ":subject:" + cipher.Digest(subject)
	if purpose == "start" {
		count = userLimit
		subjectKey = cipher.Digest("user:" + subject)
	}
	return AdmitBudgets(ctx, limit, []Budget{
		{Key: subjectKey, Count: count},
		{Key: "login:ip:" + cipher.Digest(ip), Count: ipLimit},
		{Key: "project", Count: projectLimit},
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

func (cfg LoginConfig) Budget(ctx context.Context) (int, int, int, error) {
	if cfg.BudgetSource != nil {
		user, ip, project, err := cfg.BudgetSource(ctx)
		if err != nil {
			return 0, 0, 0, domain.ErrUnavailable
		}
		return user, ip, project, nil
	}
	return cfg.UserLimitPerMinute, cfg.IPLimitPerMinute, cfg.GlobalLimitPerMinute, nil
}

func (cfg LoginConfig) AdmitFactorUser(ctx context.Context, cipher Cipher, limit Limiter, user accountdomain.UserID) error {
	operations, _, _, err := cfg.Budget(ctx)
	if err != nil {
		return err
	}
	return AdmitFactorUser(ctx, cipher, limit, operations, user)
}
