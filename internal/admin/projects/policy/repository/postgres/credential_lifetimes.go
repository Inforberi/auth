package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	accesspg "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	operators "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/sqlerrors"
	settings "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspg "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
)

type CredentialLifetimeSettings struct {
	Version int64                             `json:"version"`
	Policy  settings.CredentialLifetimePolicy `json:"policy"`
	Source  settings.SourceMetadata           `json:"source"`
}

func (r *RuntimeAuthPolicy) WithCredentialLifetimeBaseline(baseline settings.CredentialLifetimePolicy) *RuntimeAuthPolicy {
	r.credentialLifetimes = baseline
	return r
}

func (r *RuntimeAuthPolicy) ReadProjectCredentialLifetimes(ctx context.Context, actor operators.Principal, target domain.DirectoryTarget) (CredentialLifetimeSettings, error) {
	var result CredentialLifetimeSettings
	err := r.ReadDirectory(ctx, actor, target, r.registry, []operators.Permission{operators.SettingsManage}, func(ctx context.Context, tx pgx.Tx) error {
		snapshot, mode, err := settingspg.New(nil).CredentialLifetimePolicy().ReadProject(ctx, tx, r.credentialLifetimes)
		if err != nil {
			return sqlerrors.Policy(ctx, err)
		}
		result = CredentialLifetimeSettings{Version: snapshot.Version, Policy: snapshot.Policy, Source: mode.Metadata()}
		return nil
	})
	return result, err
}

func (r *RuntimeAuthPolicy) UpdateProjectCredentialLifetimes(ctx context.Context, actor operators.Principal, target domain.DirectoryTarget, expected int64, policy settings.CredentialLifetimePolicy) (CredentialLifetimeSettings, error) {
	if expected < 1 || policy.Validate() != nil {
		return CredentialLifetimeSettings{}, settings.ErrInvalidCredentialLifetime
	}
	var result CredentialLifetimeSettings
	err := r.WriteProject(ctx, actor, target, r.registry, operators.SettingsManage, func(ctx context.Context, tx pgx.Tx) error {
		if err := accesspg.LockAccessChanges(ctx, tx); err != nil {
			return sqlerrors.Catalog(ctx, err)
		}
		snapshot, err := settingspg.New(nil).CredentialLifetimePolicy().ApplyProject(ctx, tx, actor.UserID, expected, r.credentialLifetimes, policy)
		if err != nil {
			return sqlerrors.Policy(ctx, err)
		}
		result = CredentialLifetimeSettings{Version: snapshot.Version, Policy: snapshot.Policy, Source: settings.SourceAPI.Metadata()}
		return nil
	})
	return result, err
}
