package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	provisioning "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/provisioning/service"
	passwordpostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/postgres"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
)

func insertPlatformTemporary(ctx context.Context, tx pgx.Tx, user domain.UserID, email domain.AddressID, operation string, prepared provisioning.PreparedTemporaryPassword) (time.Time, error) {
	if _, err := tx.Exec(ctx, `INSERT INTO auth.account_provisions(request_key,fingerprint,user_id,platform_operation_id,
		invitation_email_id,password_change_required,temporary_password_issued_at)
		VALUES($1,$2,$3,$1,$4,true,clock_timestamp())`, operation, prepared.Fingerprint, user, email); err != nil {
		return time.Time{}, err
	}
	var expires time.Time
	err := tx.QueryRow(ctx, `INSERT INTO auth.temporary_password_credentials(user_id,email_id,password_hash,secret_digest,auth_version,expires_at)
		VALUES($1,$2,$3,$4,1,clock_timestamp()+$5::double precision*interval '1 second') RETURNING expires_at`,
		user, email, prepared.Credential.PasswordHash, prepared.Credential.SecretDigest, prepared.TTL.Seconds()).Scan(&expires)
	return expires, err
}

func reissuePlatformTemporary(ctx context.Context, tx pgx.Tx, command PlatformLifecycle) (domain.AuthVersion, error) {
	email, err := passwordpostgres.LockTemporaryReissue(ctx, tx, command.UserID, command.Temporary.Cooldown)
	if err != nil {
		return 0, err
	}
	var current domain.AuthVersion
	if err := tx.QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1`, command.UserID).Scan(&current); err != nil {
		return 0, err
	}
	if current != command.ExpectedVersion {
		return 0, domain.ErrAccountConflict
	}
	policy, err := settingspostgres.LockPublicPolicy(ctx, tx)
	if err != nil {
		return 0, err
	}
	if policy.RequireMethod("password", false) != nil {
		return 0, passworddomain.ErrTemporaryPasswordDisabled
	}
	var expires time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()+$1::double precision*interval '1 second'`, command.Temporary.TTL.Seconds()).Scan(&expires); err != nil {
		return 0, err
	}
	version, err := passwordpostgres.ReplaceTemporaryCredential(ctx, tx, command.UserID, email, command.Temporary.Credential, expires)
	if err == nil {
		command.TemporaryResult.ExpiresAt = expires
	}
	return domain.AuthVersion(version), err
}
