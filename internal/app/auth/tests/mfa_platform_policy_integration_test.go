package auth_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
)

func TestPlatformMFAManagementPolicySchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	f := newStatusFixture(t, db, ctx, "platform-only-mfa")
	accessExec(t, db, ctx, `UPDATE auth.user_emails SET verified_at=clock_timestamp() WHERE user_id=$1`, f.user)
	accessExec(t, db, ctx, `INSERT INTO auth.mfa_totp(user_id,secret,last_step) VALUES($1,$2,0)`, f.user, make([]byte, 48))
	accessExec(t, db, ctx, `INSERT INTO auth.mfa_recovery_codes(user_id,digest) VALUES($1,$2)`, f.user, strings.Repeat("a", 64))
	fresh := func() mfaservice.Proof {
		t.Helper()
		actor := renewAccessPrincipal(t, db, ctx, f.user)
		return mfaservice.Proof{UserID: f.user, TokenHash: actor.TokenHash, AuthVersion: 1}
	}
	proof := fresh()
	repo := mfapostgres.NewPlatform(db)
	local, err := mfapostgres.New(db).Status(ctx, proof)
	require.NoError(t, err)
	require.False(t, local.RequiredByPolicy, "fixture has no local Auth administrative role")
	status, err := repo.Status(ctx, proof)
	require.NoError(t, err)
	require.True(t, status.RequiredByPolicy)
	require.True(t, status.RequiredByAdministration)
	require.ErrorIs(t, repo.Disable(ctx, proof, mfadomain.CanDisableTOTP), mfadomain.ErrRequiredByPolicy)
	accessExec(t, db, ctx, `UPDATE auth.mfa_settings SET mode='required'`)
	require.ErrorIs(t, repo.Disable(ctx, proof, mfadomain.CanDisableTOTP), mfadomain.ErrRequiredByPolicy)
	accessExec(t, db, ctx, `UPDATE auth.mfa_settings SET mode='optional'`)
	status, err = repo.Status(ctx, proof)
	require.NoError(t, err)
	require.False(t, status.RequiredByPolicy)
	require.False(t, status.RequiredByAdministration)
	for _, column := range []string{"password_verified_at", "mfa_verified_at"} {
		if column == "mfa_verified_at" {
			accessExec(t, db, ctx, `UPDATE auth.sessions SET primary_verified_at=clock_timestamp()-interval '11 minutes' WHERE token_hash=$1`, proof.TokenHash)
		}
		accessExec(t, db, ctx, `UPDATE auth.sessions SET `+column+`=clock_timestamp()-interval '10 minutes' WHERE token_hash=$1`, proof.TokenHash)
		require.ErrorIs(t, repo.Disable(ctx, proof, mfadomain.CanDisableTOTP), mfadomain.ErrProofRequired)
		proof = fresh()
	}
	accessExec(t, db, ctx, `WITH r AS(INSERT INTO auth.roles(key,name,mfa_required) VALUES('operator_required','Required operator',true) RETURNING id)
 INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM r`, f.user)
	proof = fresh()
	require.ErrorIs(t, repo.Disable(ctx, proof, mfadomain.CanDisableTOTP), mfadomain.ErrRequiredByPolicy, "optional does not override role requirements")
	accessExec(t, db, ctx, `DELETE FROM auth.user_roles WHERE user_id=$1`, f.user)
	proof = fresh()
	require.NoError(t, repo.Disable(ctx, proof, mfadomain.CanDisableTOTP))
	var clean bool
	require.NoError(t, db.QueryRow(ctx, `SELECT auth_version=2
 AND NOT EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1)
 AND NOT EXISTS(SELECT 1 FROM auth.mfa_recovery_codes WHERE user_id=$1)
 AND NOT EXISTS(SELECT 1 FROM auth.sessions WHERE user_id=$1 AND revoked_at IS NULL)
 AND (SELECT count(*) FROM auth.mfa_audit WHERE user_id=$1 AND event='totp_disabled')=1 FROM auth.users WHERE id=$1`, f.user).Scan(&clean))
	require.True(t, clean)
	_, err = f.sessions.FindSession(ctx, proof.TokenHash)
	require.ErrorIs(t, err, sessiondomain.ErrSessionNotFound)
}
