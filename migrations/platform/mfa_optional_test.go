package platform_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	operators "github.com/Inforberi/financial-intelligence/internal/platform/operator/repository/postgres"
)

func operatorOptionalMFA(t *testing.T, db *pgxpool.Pool, ctx context.Context, repo *operators.Repository) {
	t.Helper()
	actor := domain.Principal{UserID: "fa630000-0000-4000-8000-000000000004", TokenHash: strings.Repeat("7", 64)}
	_, err := db.Exec(ctx, `WITH u AS(INSERT INTO auth.users(id) VALUES($1) RETURNING id),
 e AS(INSERT INTO auth.user_emails(user_id,email,verified_at) SELECT id,'optional-operator@example.test',clock_timestamp() FROM u RETURNING id,user_id)
 INSERT INTO auth.password_credentials(user_id,email_id,password_hash) SELECT user_id,id,'optional-operator-hash' FROM e`, actor.UserID)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, err := db.Exec(cleanup, `DELETE FROM auth.sessions WHERE user_id=$1`, actor.UserID)
		require.NoError(t, err)
		_, err = db.Exec(cleanup, `DELETE FROM auth.mfa_totp WHERE user_id=$1`, actor.UserID)
		require.NoError(t, err)
		_, err = db.Exec(cleanup, `DELETE FROM platform.operator_permissions WHERE user_id=$1`, actor.UserID)
		require.NoError(t, err)
		_, err = db.Exec(cleanup, `DELETE FROM auth.user_roles WHERE user_id=$1`, actor.UserID)
		require.NoError(t, err)
		_, err = db.Exec(cleanup, `DELETE FROM auth.role_permissions WHERE role_id=(SELECT id FROM auth.roles WHERE key='optional_operator_fixture');
 DELETE FROM auth.roles WHERE key='optional_operator_fixture'`)
		require.NoError(t, err)
		_, err = db.Exec(cleanup, `DELETE FROM auth.password_credentials WHERE user_id=$1`, actor.UserID)
		require.NoError(t, err)
		_, err = db.Exec(cleanup, `DELETE FROM auth.user_emails WHERE user_id=$1`, actor.UserID)
		require.NoError(t, err)
		_, err = db.Exec(cleanup, `DELETE FROM auth.users WHERE id=$1`, actor.UserID)
		require.NoError(t, err)
	})
	_, err = db.Exec(ctx, `WITH r AS(INSERT INTO auth.roles(key,name) VALUES('optional_operator_fixture','Optional operator') RETURNING id),
 p AS(INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,'auth.settings.manage' FROM r)
 INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM r`, actor.UserID)
	require.NoError(t, err)
	_, err = db.Exec(ctx, `INSERT INTO platform.operator_permissions(user_id,permission_key) VALUES($1,$2)`, actor.UserID, domain.SettingsManage)
	require.NoError(t, err)
	now := time.Now().UTC()
	proof := mfaservice.PrimaryProof{UserID: actor.UserID, AuthVersion: 1, Method: "password", Reference: "optional-operator-hash", VerifiedAt: now, Administrative: true}
	_, err = sessionpostgres.New(db).CreateSession(ctx, sessionservice.CreateSessionParams{PrimaryProof: &proof, UserID: actor.UserID, AuthVersion: 1, TokenHash: actor.TokenHash, CreatedAt: now, ExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour)})
	require.NoError(t, err)
	current, err := repo.ReadMFAPolicy(ctx, actor)
	require.NoError(t, err)
	require.Equal(t, settingsdomain.MFAOptional, current.Policy.Mode)
	change := settingsservice.MFAChange{ExpectedVersion: current.Version, Policy: current.Policy}
	_, err = repo.UpdateMFAPolicy(ctx, actor, change, false)
	require.NoError(t, err, "optional operator mutation needs a fresh password without hidden MFA enrollment")
	_, err = db.Exec(ctx, `UPDATE auth.sessions SET password_verified_at=clock_timestamp()-interval '10 minutes' WHERE token_hash=$1`, actor.TokenHash)
	require.NoError(t, err)
	_, err = repo.UpdateMFAPolicy(ctx, actor, change, false)
	require.ErrorIs(t, err, domain.ErrFreshAuthRequired)
	_, err = db.Exec(ctx, `UPDATE auth.sessions SET password_verified_at=clock_timestamp() WHERE token_hash=$1`, actor.TokenHash)
	require.NoError(t, err)
	_, err = db.Exec(ctx, `INSERT INTO auth.mfa_totp(user_id,secret,last_step) VALUES($1,$2,0)`, actor.UserID, make([]byte, 48))
	require.NoError(t, err)
	_, err = repo.ReadMFAPolicy(ctx, actor)
	require.ErrorIs(t, err, domain.ErrForbidden, "enrolled protection survives optional mode")
}
