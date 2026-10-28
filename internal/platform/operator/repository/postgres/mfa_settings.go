package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
)

func (r *Repository) ReadMFAPolicy(ctx context.Context, actor domain.Principal) (settingsdomain.MFASnapshot, error) {
	if !actor.Valid() {
		return settingsdomain.MFASnapshot{}, domain.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var s settingsdomain.MFASnapshot
	err := r.db.QueryRow(ctx, `SELECT version,mode FROM auth.mfa_settings WHERE singleton AND `+operatorReadGuard,
		r.realm, actor.UserID, actor.TokenHash, domain.SettingsManage).Scan(&s.Version, &s.Policy.Mode)
	if errors.Is(err, pgx.ErrNoRows) {
		return settingsdomain.MFASnapshot{}, domain.ErrForbidden
	}
	if err != nil {
		return settingsdomain.MFASnapshot{}, errors.Join(domain.ErrUnavailable, ctx.Err())
	}
	return s, nil
}

// ready is the platform assembly capability, not the selected mode or a project capability.
func (r *Repository) UpdateMFAPolicy(ctx context.Context, actor domain.Principal, input settingsservice.MFAChange, ready bool) (settingsdomain.MFASnapshot, error) {
	if !actor.Valid() {
		return settingsdomain.MFASnapshot{}, domain.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return settingsdomain.MFASnapshot{}, errors.Join(domain.ErrUnavailable, ctx.Err())
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		_ = tx.Rollback(cleanup) //nolint:gosec // Commit closes the transaction; preserve its error.
	}()
	if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
		return settingsdomain.MFASnapshot{}, errors.Join(domain.ErrUnavailable, ctx.Err())
	}
	if _, err := r.AuthorizeMutation(ctx, tx, actor, domain.SettingsManage, 5*time.Minute); err != nil {
		return settingsdomain.MFASnapshot{}, err
	}
	result, err := settingspostgres.ApplyMFAPolicyChange(ctx, tx, actor.UserID, input, ready)
	if err != nil {
		return settingsdomain.MFASnapshot{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return settingsdomain.MFASnapshot{}, errors.Join(domain.ErrUnavailable, ctx.Err())
	}
	return result, nil
}
