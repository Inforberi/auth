package platform_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	operators "github.com/Inforberi/financial-intelligence/internal/platform/operator/repository/postgres"
)

func operatorMFAPolicy(t *testing.T, db *pgxpool.Pool, ctx context.Context, repo, wrong *operators.Repository, actor domain.Principal) {
	t.Helper()
	before, err := repo.ReadMFAPolicy(ctx, actor)
	require.NoError(t, err)
	require.Equal(t, int64(1), before.Version)
	require.Equal(t, settingsdomain.MFAAdministrators, before.Policy.Mode)
	initialToken := actor.TokenHash
	var initialRevision int64
	require.NoError(t, db.QueryRow(ctx, `SELECT session_revision FROM auth.mfa_settings WHERE singleton`).Scan(&initialRevision))
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, err := db.Exec(cleanup, `DELETE FROM auth.mfa_settings_audit WHERE actor_id=$1`, actor.UserID)
		require.NoError(t, err)
		_, err = db.Exec(cleanup, `UPDATE auth.mfa_settings SET version=$1,mode=$2,session_revision=$3 WHERE singleton`, before.Version, before.Policy.Mode, initialRevision)
		require.NoError(t, err)
		if actor.TokenHash != initialToken {
			_, err = db.Exec(cleanup, `DELETE FROM auth.sessions WHERE token_hash=$1 AND user_id=$2`, actor.TokenHash, actor.UserID)
			require.NoError(t, err)
		}
		_, err = db.Exec(cleanup, `INSERT INTO platform.operator_permissions(user_id,permission_key) VALUES($1,$2) ON CONFLICT DO NOTHING`, actor.UserID, domain.SettingsManage)
		require.NoError(t, err)
	})
	_, err = wrong.ReadMFAPolicy(ctx, actor)
	require.ErrorIs(t, err, domain.ErrForbidden)
	input := settingsservice.MFAChange{ExpectedVersion: before.Version, Policy: before.Policy}
	_, err = wrong.UpdateMFAPolicy(ctx, actor, input, true)
	require.ErrorIs(t, err, domain.ErrForbidden)
	got, err := repo.UpdateMFAPolicy(ctx, actor, input, false)
	require.NoError(t, err)
	require.Equal(t, before, got)
	input.Policy.Mode = settingsdomain.MFARequired
	_, err = repo.UpdateMFAPolicy(ctx, actor, input, false)
	require.ErrorIs(t, err, settingsdomain.ErrMethodNotReady)
	got, err = repo.UpdateMFAPolicy(ctx, actor, input, true)
	require.NoError(t, err)
	require.Equal(t, before.Version+1, got.Version)
	actor.TokenHash = strings.Repeat("6", 64)
	_, err = db.Exec(ctx, `INSERT INTO auth.sessions(token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,
 primary_method,primary_verified_at,password_verified_at,mfa_verified_at,mfa_method,user_agent,ip_address)
 SELECT $1,id,auth_version,statement_timestamp(),statement_timestamp()+interval '1 hour',statement_timestamp()+interval '2 hours',
 'password',statement_timestamp(),statement_timestamp(),statement_timestamp(),'totp','MFA policy fixture','192.0.2.1' FROM auth.users WHERE id=$2`, actor.TokenHash, actor.UserID)
	require.NoError(t, err)

	_, err = repo.UpdateMFAPolicy(ctx, actor, input, true)
	require.ErrorIs(t, err, settingsdomain.ErrPolicyConflict)
	input.ExpectedVersion, input.Policy.Mode = got.Version, settingsdomain.MFAOptional
	_, err = db.Exec(ctx, `ALTER TABLE auth.mfa_settings_audit ADD CONSTRAINT reject_platform_mfa CHECK(version<3) NOT VALID`)
	require.NoError(t, err)
	_, err = repo.UpdateMFAPolicy(ctx, actor, input, true)
	require.Error(t, err)
	read, err := repo.ReadMFAPolicy(ctx, actor)
	require.NoError(t, err)
	require.Equal(t, got, read, "audit failure must roll back platform settings")
	_, err = db.Exec(ctx, `ALTER TABLE auth.mfa_settings_audit DROP CONSTRAINT reject_platform_mfa`)
	require.NoError(t, err)
	got, err = repo.UpdateMFAPolicy(ctx, actor, input, false)
	require.NoError(t, err)
	require.Equal(t, settingsdomain.MFAOptional, got.Policy.Mode)
	t.Run("optional operator authority", func(t *testing.T) { operatorOptionalMFA(t, db, ctx, repo) })
	var factors, audits int
	require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.mfa_totp WHERE user_id=$1`, actor.UserID).Scan(&factors))
	require.Equal(t, 1, factors, "saving optional must not delete the owner's factor")
	require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.mfa_settings_audit WHERE actor_id=$1`, actor.UserID).Scan(&audits))
	require.Equal(t, 2, audits)
	_, err = db.Exec(ctx, `DELETE FROM platform.operator_permissions WHERE user_id=$1 AND permission_key=$2`, actor.UserID, domain.SettingsManage)
	require.NoError(t, err)
	_, err = repo.ReadMFAPolicy(ctx, actor)
	require.ErrorIs(t, err, domain.ErrForbidden)
	input.ExpectedVersion = got.Version
	_, err = repo.UpdateMFAPolicy(ctx, actor, input, true)
	require.ErrorIs(t, err, domain.ErrForbidden, "local Auth roles must not substitute platform permission")
	_, err = db.Exec(ctx, `INSERT INTO platform.operator_permissions(user_id,permission_key) VALUES($1,$2)`, actor.UserID, domain.SettingsManage)
	require.NoError(t, err)
}
