package auth

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfatotp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
)

type projectMFARecovery struct {
	mfa  *projectMFA
	mail *projectEmailRuntime
}

func (p *ProjectProfile) buildProfileMFARecovery(ctx context.Context, cfg ProjectProfileConfig, root string, redisReady bool) {
	requested := false
	for _, view := range configuredBrowserPolicies(cfg) {
		requested = requested || view.mfa.RecoveryEnabled
	}
	if !requested {
		return
	}
	if !cfg.BrowserEnabled {
		p.state("mfa_recovery", "browser_disabled")
		return
	}
	mfa := p.mfa
	if mfa == nil {
		mfa = p.mfaManagement
	}
	if mfa == nil {
		p.state("mfa_recovery", "mfa_unavailable")
		return
	}
	if reason := p.mailReason(redisReady); reason != "" {
		p.state("mfa_recovery", reason)
		return
	}
	mail, err := newProjectEmailRuntime(p.key, root, p.deps.Delivery.cfg.SMTPAllowedTargets, ProjectSMTPDependencies{Registry: p.deps.Registry, Reader: p.deps.Reader, Redis: p.deps.Redis})
	if err != nil {
		p.feature("mfa_recovery", err)
		return
	}
	recovery := &projectMFARecovery{mfa: mfa, mail: mail}
	if err := recovery.use(ctx, func(context.Context, *mfaservice.Recovery) error { return nil }); err != nil {
		p.state("mfa_recovery", "recovery_dependencies_unavailable")
		return
	}
	p.mfaRecovery = recovery
	p.state("mfa_recovery", "")
}

func (p *projectMFARecovery) use(ctx context.Context, operation func(context.Context, *mfaservice.Recovery) error) error {
	if p == nil || p.mfa == nil || p.mail == nil {
		return domain.ErrUnavailable
	}
	return p.mfa.use(ctx, func(ctx context.Context, pool *pgxpool.Pool) error {
		repo := mfapostgres.New(pool)
		// Runtime may request/complete recovery, but must never approve it.
		if err := repo.CheckRecoveryOperator(ctx); err != nil {
			return domain.ErrUnavailable
		}
		if _, err := p.mail.smtp.credentialsInPool(ctx, pool); err != nil {
			return domain.ErrUnavailable
		}
		factory := p.mfa.factory
		service, err := mfaservice.NewRecovery(repo, factory.cipher, mfatotp.Authenticator{}, factory.limits, factory.managementConfig, factory.config.AllowPrimary)
		if err != nil {
			return err
		}
		return operation(ctx, service)
	})
}

func (p *projectMFARecovery) Start(ctx context.Context, input mfaservice.StartRecoveryInput) (*mfaservice.RecoveryCandidate, error) {
	var result *mfaservice.RecoveryCandidate
	err := p.use(ctx, func(ctx context.Context, service *mfaservice.Recovery) error {
		var err error
		result, err = service.Start(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *projectMFARecovery) Complete(ctx context.Context, input mfaservice.CompleteRecoveryInput) (*mfaservice.RecoveryCodes, error) {
	var result *mfaservice.RecoveryCodes
	err := p.use(ctx, func(ctx context.Context, service *mfaservice.Recovery) error {
		var err error
		result, err = service.Complete(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
