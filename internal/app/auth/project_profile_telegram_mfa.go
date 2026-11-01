package auth

import (
	"github.com/jackc/pgx/v5/pgxpool"

	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
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
	security := realmSecurity{scope: scope}
	token, err := security.cipher(root, "telegram-bot-token:v1")
	if err != nil {
		p.feature("telegram_mfa", err)
		return
	}
	webhook, err := security.cipher(root, "telegram-webhook:v1")
	if err != nil {
		p.feature("telegram_mfa", err)
		return
	}
	channel, err := security.cipher(root, "telegram-channel:v1")
	if err != nil {
		p.feature("telegram_mfa", err)
		return
	}
	p.telegramMFA = &projectTelegramMFA{profile: p, manager: p.mfaManagement, client: p.deps.BotAPI, token: token, webhook: webhook, channel: channel}
	p.state("telegram_mfa", "")
}

func (p *ProjectProfile) bindFactorSelection() {
	var factories []*projectMFALogin
	if p.password != nil && p.password.projectMFA != nil {
		factories = append(factories, p.password.factory)
	}
	if p.tokens != nil && p.tokens.native != nil {
		factories = append(factories, p.tokens.native.mfa)
	}
	for _, factory := range factories {
		email := p.emailMFA
		if p.tokens != nil && p.tokens.native != nil && factory == p.tokens.native.mfa {
			email = p.tokens.native.emailMFA
		}
		if email != nil {
			factory.email = func(pool *pgxpool.Pool) (mfaservice.FactorStarter, error) { return email.login(pool) }
		}
		if p.telegramMFA != nil {
			factory.telegram = func(pool *pgxpool.Pool) (mfaservice.FactorStarter, error) { return p.telegramMFA.login(pool, factory) }
		}
	}
}
