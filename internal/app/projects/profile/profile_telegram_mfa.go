package profile

import (
	"github.com/jackc/pgx/v5/pgxpool"

	projectmfa "github.com/Inforberi/financial-intelligence/internal/app/projects/mfa"
	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
)

func (p *ProjectProfile) buildProfileTelegramMFA(cfg ProjectProfileConfig, root string) {
	if !cfg.TelegramMFA {
		return
	}
	if p.mfaManagement == nil || p.mfaRecovery == nil || p.password == nil || p.deps.BotAPI == nil {
		p.state("telegram_mfa", "password_mfa_recovery_required")
		return
	}
	scope, err := realmscope.New("project", string(p.key.Binding.ProjectID))
	if err != nil {
		p.feature("telegram_mfa", err)
		return
	}

	p.telegramMFA, err = projectmfa.NewProjectTelegramMFA(p.mfaManagement, p.deps.BotAPI, p.origin, p.deliveryReady, scope, root)
	if err != nil {
		p.feature("telegram_mfa", err)
		return
	}
	p.state("telegram_mfa", "")
}

func (p *ProjectProfile) bindFactorSelection() {
	var factories []*projectmfa.ProjectMFALogin
	if p.password != nil && p.password.ProjectMFA != nil {
		factories = append(factories, p.password.Factory())
	}
	if p.tokens != nil && p.tokens.NativeAvailable() {
		factories = append(factories, p.tokens.NativeFactory())
	}
	for _, factory := range factories {
		email := p.emailMFA
		if p.tokens != nil && p.tokens.NativeAvailable() && factory == p.tokens.NativeFactory() {
			email = p.tokens.NativeEmailMFA()
		}
		if email != nil {
			factory.BindEmail(func(pool *pgxpool.Pool) (mfalogin.FactorStarter, error) { return email.Login(pool) })
		}
		if p.telegramMFA != nil {
			factory.BindTelegram(func(pool *pgxpool.Pool) (mfalogin.FactorStarter, error) { return p.telegramMFA.Login(pool, factory) })
		}
	}
}
