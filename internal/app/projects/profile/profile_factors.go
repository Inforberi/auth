package profile

import (
	"github.com/jackc/pgx/v5/pgxpool"

	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	projectmfa "github.com/Inforberi/financial-intelligence/internal/auth/project/mfa"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
)

func (p *profileAssembly) buildProfileEmailMFA(cfg runtimeprofile.ProjectProfileConfig) {
	if cfg.EmailMFA == nil {
		return
	}
	if err := cfg.EmailMFA.Validate(); err != nil {
		p.feature("email_mfa", err)
		return
	}
	if !cfg.EmailMFARecoveryConfigured() {
		p.state("email_mfa", "password_mfa_recovery_required")
		return
	}
	if p.mfaManagement == nil || p.mfaRecovery == nil {
		p.state("email_mfa", "mfa_recovery_unavailable")
		return
	}
	p.emailMFA = p.mfaRecovery.NewEmailFactor(p.mfaManagement, *cfg.EmailMFA)
	p.state("email_mfa", "")
	if p.featureReady("password") {
		p.state("email_mfa_login", "")
	}
	if p.tokens != nil && p.tokens.NativePasswordEnabled() {
		p.tokens.BindEmailMFA(p.emailMFA, cfg.Timeout)
		if p.featureReady("native_password") {
			p.state("native_email_mfa", "")
		}
	}
}

func (p *profileAssembly) buildProfileTelegramMFA(cfg runtimeprofile.ProjectProfileConfig, root string) {
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

func (p *profileAssembly) bindFactorSelection() {
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
