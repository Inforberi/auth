package profile

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	projectaccess "github.com/Inforberi/financial-intelligence/internal/access/project"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projectaccount "github.com/Inforberi/financial-intelligence/internal/auth/project/account"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/auth/project/methods"
	projectmfa "github.com/Inforberi/financial-intelligence/internal/auth/project/mfa"
	projectbinding "github.com/Inforberi/financial-intelligence/internal/auth/project/runtime"
	projectsettings "github.com/Inforberi/financial-intelligence/internal/auth/project/settings"
	projectnative "github.com/Inforberi/financial-intelligence/internal/auth/project/token"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
)

func (p *ProjectProfile) runtimeBinding() projectbinding.Binding {
	return projectbinding.Binding{Key: p.key, Registry: p.deps.Registry, Reader: p.deps.Reader}
}

type ProjectProfile struct {
	key                      projectruntime.Key
	origin                   string
	policy                   settingsdomain.Snapshot
	deps                     ProjectProfileDependencies
	states                   map[string]ProjectFeatureState
	observedAt               time.Time
	password                 *projectmethods.ProjectPassword
	emailOTP                 *projectmethods.ProjectEmailOTP
	google, telegram         *projectmethods.ProjectOIDC
	verification, recovery   *projectaccount.ProjectEmail
	binding, change          *projectaccount.ProjectEmail
	provisioning, activation *projectaccount.ProjectEmail
	bindingConfirmation      *projectaccount.ProjectEmail
	changeProtection         *projectaccount.ProjectEmail
	tokens                   *projectnative.ProjectTokens
	mfa                      *projectmfa.ProjectMFA
	mfaManagement            *projectmfa.ProjectMFA
	mfaRecovery              *projectmfa.ProjectMFARecovery
	emailMFA                 *projectmfa.ProjectEmailMFA
	telegramMFA              *projectmfa.ProjectTelegramMFA
	userDirectory            *projectaccount.ProjectUserDirectory
	userLifecycle            *projectaccount.ProjectUserLifecycle
	access                   *projectaccess.ProjectAccess
	authSettings             *projectsettings.ProjectAuthSettings
	smtpSettings             *projectsettings.ProjectSMTPSettings
	providerSettings         *projectsettings.ProjectProviderSettings
	retentionSettings        *projectsettings.ProjectRetentionSettings
	mfaSettings              *projectsettings.ProjectMFASettings
}

// CheckCurrent rejects a stale route plan; the caller must rebuild it after a conflict.
func (p *ProjectProfile) CheckCurrent(ctx context.Context) error {
	return p.checkSnapshotCurrent(ctx, p.policy)
}

func (p *ProjectProfile) checkSnapshotCurrent(ctx context.Context, observed settingsdomain.Snapshot) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	currentKey, err := p.deps.Reader.ResolveRuntime(ctx, p.origin)
	if err != nil {
		return err
	}
	if currentKey != p.key {
		return projectdomain.ErrConflict
	}
	return p.checkPolicySnapshot(ctx, observed)
}

func (p *ProjectProfile) checkPolicyCurrent(ctx context.Context) error {
	return p.checkPolicySnapshot(ctx, p.policy)
}

func (p *ProjectProfile) checkPolicySnapshot(ctx context.Context, observed settingsdomain.Snapshot) error {
	return p.deps.Registry.UsePool(ctx, p.key, func(ctx context.Context, pool *pgxpool.Pool) error {
		current, err := settingspostgres.New(pool).Load(ctx)
		if err != nil {
			return err
		}
		if current != observed {
			return settingsdomain.ErrPolicyConflict
		}
		return projectbinding.RequireCurrent(ctx, p.deps.Reader, p.key)
	})
}
