package mfa

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	runtimepostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime/repository/postgres"
	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	mfarecovery "github.com/Inforberi/financial-intelligence/internal/auth/mfa/recovery/service"
	projectaccount "github.com/Inforberi/financial-intelligence/internal/auth/project/account"
)

func BindProjectMFA(factory *ProjectMFALogin, key projectruntime.Key, registry *projectruntime.Registry, reader *runtimepostgres.RuntimeCredentialReader, timeout time.Duration, emailProof bool) *ProjectMFA {
	return &ProjectMFA{factory: factory, key: key, registry: registry, reader: reader, timeout: timeout, emailProof: emailProof}
}

func (p *ProjectMFA) Factory() *ProjectMFALogin { return p.factory }

func (f *ProjectMFALogin) BindPrimary(allow func(string, string) bool) { f.config.AllowPrimary = allow }

func (f *ProjectMFALogin) BindEmail(start func(*pgxpool.Pool) (mfalogin.FactorStarter, error)) {
	f.email = start
}

func (f *ProjectMFALogin) BindTelegram(start func(*pgxpool.Pool) (mfalogin.FactorStarter, error)) {
	f.telegram = start
}

func NewProjectMFARecovery(mfa *ProjectMFA, mail *projectaccount.ProjectEmailRuntime) *ProjectMFARecovery {
	return &ProjectMFARecovery{mfa: mfa, mail: mail}
}

func (r *ProjectMFARecovery) CheckDependencies(ctx context.Context) error {
	return r.use(ctx, func(context.Context, *mfarecovery.Recovery) error { return nil })
}

func (r *ProjectMFARecovery) NewEmailFactor(manager *ProjectMFA, cfg ProjectEmailMFAConfig) *ProjectEmailMFA {
	return &ProjectEmailMFA{mfa: manager, mail: r.mail, cfg: cfg}
}

func (p *ProjectEmailMFA) WithRuntime(mfa *ProjectMFA) *ProjectEmailMFA {
	return &ProjectEmailMFA{mfa: mfa, mail: p.mail, cfg: p.cfg}
}

func (p *ProjectEmailMFA) CheckSMTP(ctx context.Context, pool *pgxpool.Pool) error {
	return p.mail.CheckSMTP(ctx, pool)
}

func NewProjectPreferences(manager *ProjectMFA) projectMFAPreferences {
	return projectMFAPreferences{manager: manager}
}

func NewProjectRecoveryPrimary(manager *ProjectMFA) ProjectRecoveryPrimary {
	return ProjectRecoveryPrimary{manager: manager}
}
