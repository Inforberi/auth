package postgres

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
)

func TestMFAPolicySettingsSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	accessExec(t, db, ctx, `CREATE ROLE auth_mfa_settings_runtime LOGIN PASSWORD 'synthetic-recovery-only';
 GRANT USAGE ON SCHEMA auth TO auth_mfa_settings_runtime;
 GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA auth TO auth_mfa_settings_runtime`)
	t.Cleanup(func() {
		accessExec(t, db, ctx, `DROP OWNED BY auth_mfa_settings_runtime; DROP ROLE auth_mfa_settings_runtime`)
	})
	runtime := operatorPool(t, ctx, db, "auth_mfa_settings_runtime")
	repo := settingspostgres.New(runtime)
	svc, unavailable := settingsservice.NewMFA(repo, true), settingsservice.NewMFA(repo, false)
	before, err := svc.Current(ctx)
	require.NoError(t, err)
	require.Equal(t, settingsdomain.MFASnapshot{Version: 1, Policy: settingsdomain.MFAPolicy{Mode: settingsdomain.MFAAdministrators}}, before)
	actor := accessPrincipal(t, db, ctx)
	_, err = svc.Read(ctx, actor)
	require.ErrorIs(t, err, accessdomain.ErrForbidden)
	accessExec(t, db, ctx, `WITH r AS(INSERT INTO auth.roles(key,name) VALUES('mfa_settings_operator','Operator') RETURNING id),
 p AS(INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,'auth.settings.manage' FROM r)
 INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM r`, actor.UserID)
	read, err := svc.Read(ctx, actor)
	require.NoError(t, err)
	require.Equal(t, before, read)
	input := settingsservice.MFAUpdateInput{Actor: actor, MFAChange: settingsservice.MFAChange{ExpectedVersion: before.Version, Policy: before.Policy}}
	got, err := unavailable.Update(ctx, input)
	require.NoError(t, err, "no-op must not require currently available MFA")
	require.Equal(t, before, got)
	input.Policy.Mode = "unknown"
	_, err = svc.Update(ctx, input)
	require.ErrorIs(t, err, settingsdomain.ErrInvalidMFAPolicy)
	input.Policy.Mode = settingsdomain.MFARequired
	_, err = unavailable.Update(ctx, input)
	require.ErrorIs(t, err, settingsdomain.ErrMethodNotReady)
	got, err = svc.Update(ctx, input)
	require.NoError(t, err)
	require.Equal(t, int64(2), got.Version)
	require.Equal(t, settingsdomain.MFARequired, got.Policy.Mode)
	actor = renewAccessPrincipal(t, db, ctx, actor.UserID)
	input.Actor = actor
	_, err = svc.Update(ctx, input)
	require.ErrorIs(t, err, settingsdomain.ErrPolicyConflict)
	input.ExpectedVersion, input.Policy.Mode = got.Version, settingsdomain.MFAOptional
	accessExec(t, db, ctx, `ALTER TABLE auth.mfa_settings_audit ADD CONSTRAINT reject_mfa_policy CHECK(version<3) NOT VALID`)
	_, err = svc.Update(ctx, input)
	require.Error(t, err)
	read, err = svc.Current(ctx)
	require.NoError(t, err)
	require.Equal(t, got, read, "audit failure must roll back the settings update")
	accessExec(t, db, ctx, `ALTER TABLE auth.mfa_settings_audit DROP CONSTRAINT reject_mfa_policy`)
	other := input
	other.Policy.Mode = settingsdomain.MFAAdministrators
	a, b := protectionPair(func() error { _, err := svc.Update(ctx, input); return err }, func() error { _, err := svc.Update(ctx, other); return err })
	require.True(t, a == nil && errors.Is(b, settingsdomain.ErrPolicyConflict) || b == nil && errors.Is(a, settingsdomain.ErrPolicyConflict), "exactly one concurrent version may commit: %v / %v", a, b)
	read, err = svc.Current(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(3), read.Version)
	input.ExpectedVersion, input.Policy.Mode = read.Version, settingsdomain.MFAOptional
	got, err = unavailable.Update(ctx, input)
	require.NoError(t, err)
	accessExec(t, db, ctx, `UPDATE auth.roles SET mfa_required=true WHERE key='mfa_settings_operator'`)
	var roleRequired bool
	require.NoError(t, db.QueryRow(ctx, `SELECT auth.role_requires_mfa($1)`, actor.UserID).Scan(&roleRequired))
	require.True(t, roleRequired, "saving optional must not erase role requirements")
	var audits int64
	require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.mfa_settings_audit`).Scan(&audits))
	require.Equal(t, got.Version-1, audits, "no-op and rejected changes must not add audit records")
	accessExec(t, db, ctx, `UPDATE auth.sessions SET password_verified_at=clock_timestamp()-interval '10 minutes' WHERE token_hash=$1`, actor.TokenHash)
	input.ExpectedVersion, input.Policy.Mode = got.Version, settingsdomain.MFARequired
	_, err = svc.Update(ctx, input)
	require.ErrorIs(t, err, accessdomain.ErrFreshAuthRequired)
	expectSQLState(t, db, ctx, "23514", `UPDATE auth.mfa_settings SET mode='disabled'`)
	expectSQLState(t, db, ctx, "23514", `UPDATE auth.mfa_settings SET version=0`)
	accessExec(t, db, ctx, `DELETE FROM auth.mfa_settings`)
	_, err = svc.Current(ctx)
	require.ErrorIs(t, err, settingsdomain.ErrNotInitialized)
	_, err = svc.Read(ctx, actor)
	require.ErrorIs(t, err, accessdomain.ErrForbidden)
	var rows int
	require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.mfa_settings`).Scan(&rows))
	require.Zero(t, rows, "runtime reads must not recreate missing settings")
}
