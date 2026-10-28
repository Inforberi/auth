package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

const mfaColumns = `version,mode`

func scanMFA(row pgx.Row) (domain.MFASnapshot, error) {
	var s domain.MFASnapshot
	err := row.Scan(&s.Version, &s.Policy.Mode)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.MFASnapshot{}, domain.ErrNotInitialized
	}
	return s, err
}

func (r *Repository) LoadMFAPolicy(ctx context.Context) (domain.MFASnapshot, error) {
	return scanMFA(r.db.QueryRow(ctx, `SELECT `+mfaColumns+` FROM auth.mfa_settings WHERE singleton`))
}

func (r *Repository) ReadMFAPolicy(ctx context.Context, actor accessservice.Principal) (domain.MFASnapshot, error) {
	s, err := scanMFA(r.db.QueryRow(ctx, `SELECT `+mfaColumns+` FROM auth.mfa_settings WHERE singleton AND `+settingsReadGuard,
		actor.UserID, actor.TokenHash, settings.AuthSettingsManage))
	if errors.Is(err, domain.ErrNotInitialized) {
		return domain.MFASnapshot{}, accessdomain.ErrForbidden
	}
	return s, err
}

// ReadMFAPolicyInTransaction validates the migration seed without repairing missing configuration.
func ReadMFAPolicyInTransaction(ctx context.Context, tx pgx.Tx) (domain.MFASnapshot, error) {
	s, err := scanMFA(tx.QueryRow(ctx, `SELECT `+mfaColumns+` FROM auth.mfa_settings WHERE singleton FOR SHARE`))
	if err != nil {
		return domain.MFASnapshot{}, err
	}
	return s, s.Policy.Validate()
}
