package postgres

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
)

func TestMFAPolicyEnforcementSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	f := newStatusFixture(t, db, ctx, "realm-policy")
	g := newStatusFixture(t, db, ctx, "realm-enrollment")
	actor := accessPrincipal(t, db, ctx)
	accessExec(t, db, ctx, `WITH r AS(INSERT INTO auth.roles(key,name) VALUES('realm_policy_manager','Manager') RETURNING id),
 p AS(INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,'auth.settings.manage' FROM r)
 INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM r`, actor.UserID)
	svc := settingsservice.NewMFA(settingspostgres.New(db), true)
	change := settingsservice.MFAUpdateInput{Actor: actor, MFAChange: settingsservice.MFAChange{ExpectedVersion: 1, Policy: settingsdomain.MFAPolicy{Mode: settingsdomain.MFAOptional}}}
	optional, err := svc.Update(ctx, change)
	require.NoError(t, err)
	accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM auth.roles WHERE key='realm_policy_manager'`, f.user)
	accessExec(t, db, ctx, `UPDATE auth.user_emails SET verified_at=clock_timestamp() WHERE user_id=$1`, f.user)
	proof := mfaservice.PrimaryProof{UserID: f.user, AuthVersion: 1, Method: "password", Reference: "old-hash", VerifiedAt: time.Now().UTC(), Administrative: true}
	params := f.params
	params.TokenHash, params.PrimaryProof = strings.Repeat("c", 64), &proof
	_, err = f.sessions.CreateSession(ctx, params)
	require.NoError(t, err, "optional administrator without factor must get a password session")
	plainAdmin := accessservice.Principal{UserID: f.user, TokenHash: params.TokenHash}
	input := settingsservice.MFAUpdateInput{Actor: plainAdmin, MFAChange: settingsservice.MFAChange{ExpectedVersion: optional.Version, Policy: optional.Policy}}
	_, err = svc.Update(ctx, input)
	require.NoError(t, err, "sensitive optional action still requires a fresh password, not a hidden MFA enrollment")
	accessExec(t, db, ctx, `INSERT INTO auth.mfa_totp(user_id,secret,last_step) VALUES($1,$2,0)`, f.user, make([]byte, 48))
	params.TokenHash = strings.Repeat("d", 64)
	_, err = f.sessions.CreateSession(ctx, params)
	require.ErrorIs(t, err, sessiondomain.ErrMFARequired, "optional must preserve enrolled protection")
	mfa := mfapostgres.New(db)
	digest, binding := strings.Repeat("e", 64), strings.Repeat("f", 64)
	_, err = mfa.SaveLoginChallenge(ctx, proof, digest, binding, time.Minute)
	require.NoError(t, err)
	change.ExpectedVersion, change.Policy.Mode = optional.Version, settingsdomain.MFARequired
	originalSession := g.params.TokenHash
	g.params.TokenHash = strings.Repeat("a", 64)
	var required settingsdomain.MFASnapshot
	a, b := protectionPair(func() error { _, err := g.sessions.CreateSession(ctx, g.params); return err }, func() error {
		var err error
		required, err = svc.Update(ctx, change)
		return err
	})
	require.NoError(t, b)
	require.True(t, a == nil || errors.Is(a, sessiondomain.ErrMFARequired), "concurrent issuance: %v", a)
	_, err = g.sessions.FindSession(ctx, g.params.TokenHash)
	require.ErrorIs(t, err, sessiondomain.ErrSessionNotFound, "late primary session must not survive tightening")
	_, err = mfa.FindLoginOwner(ctx, digest, binding)
	require.ErrorIs(t, err, mfadomain.ErrInvalidCode, "pending login must bind the policy revision")
	gp := mfaservice.PrimaryProof{UserID: g.user, AuthVersion: 1, Method: "password", Reference: "old-hash", VerifiedAt: time.Now().UTC()}
	enrollmentDigest := strings.Repeat("b", 64)
	state, err := mfa.SaveLoginChallenge(ctx, gp, enrollmentDigest, binding, time.Minute)
	require.NoError(t, err)
	require.True(t, state.EnrollmentRequired)
	_, err = mfa.SaveLoginEnrollment(ctx, mfaservice.LoginEnrollmentParams{ChallengeDigest: enrollmentDigest, BindingHash: binding, EnrollmentDigest: strings.Repeat("9", 64), Secret: make([]byte, 48)})
	require.NoError(t, err)
	_, err = g.sessions.CreateSession(ctx, g.params)
	require.ErrorIs(t, err, sessiondomain.ErrMFARequired, "pending enrollment is not a session")
	actor = renewAccessPrincipal(t, db, ctx, actor.UserID)
	change.Actor, change.ExpectedVersion, change.Policy.Mode = actor, required.Version, settingsdomain.MFAOptional
	_, err = svc.Update(ctx, change)
	require.NoError(t, err)
	_, err = f.sessions.FindSession(ctx, plainAdmin.TokenHash)
	require.ErrorIs(t, err, sessiondomain.ErrSessionNotFound)
	_, err = g.sessions.FindSession(ctx, g.params.TokenHash)
	require.ErrorIs(t, err, sessiondomain.ErrSessionNotFound, "relaxation must not revive a closed primary session")
	_, err = g.sessions.FindSession(ctx, originalSession)
	require.ErrorIs(t, err, sessiondomain.ErrSessionNotFound, "original session cannot revive after relaxation")
	_, err = mfa.FindLoginOwner(ctx, digest, binding)
	require.ErrorIs(t, err, mfadomain.ErrInvalidCode, "relaxation must not revive an old challenge")
	_, err = f.sessions.CreateSession(ctx, params)
	require.ErrorIs(t, err, sessiondomain.ErrMFARequired)
	expectSQLState(t, db, ctx, "P0001", `UPDATE auth.sessions SET mfa_policy_revision=mfa_policy_revision+1`)
}

func TestMFAPolicyDisabledCapabilitySchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	repo := mfapostgres.New(db)
	require.NoError(t, repo.CheckDisabled(ctx))
	accessExec(t, db, ctx, `UPDATE auth.mfa_settings SET mode='required'`)
	require.Error(t, repo.CheckDisabled(ctx), "required realm cannot run without MFA capability")
	accessExec(t, db, ctx, `UPDATE auth.mfa_settings SET mode='optional'`)
	require.NoError(t, repo.CheckDisabled(ctx))
	accessExec(t, db, ctx, `WITH u AS(INSERT INTO auth.users DEFAULT VALUES RETURNING id),
 r AS(INSERT INTO auth.roles(key,name,system) VALUES('super_admin','Administrator',true) RETURNING id)
 INSERT INTO auth.user_roles(user_id,role_id) SELECT u.id,r.id FROM u CROSS JOIN r`)
	require.NoError(t, repo.CheckDisabled(ctx), "optional administrator must not force a technical MFA dependency")
	accessExec(t, db, ctx, `UPDATE auth.mfa_settings SET mode='administrators'`)
	require.Error(t, repo.CheckDisabled(ctx), "required administrator cannot run without MFA capability")
}

func TestMFACapabilitySchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	repo := mfapostgres.New(db)
	for _, mode := range []settingsdomain.MFAMode{settingsdomain.MFAOptional, settingsdomain.MFAAdministrators, settingsdomain.MFARequired} {
		t.Run(string(mode), func(t *testing.T) {
			accessExec(t, db, ctx, `UPDATE auth.mfa_settings SET mode=$1`, mode)
			require.NoError(t, repo.CheckCapability(ctx, true))
			err := repo.CheckCapability(ctx, false)
			if mode == settingsdomain.MFARequired {
				require.Error(t, err)
			} else {
				require.NoError(t, err, "empty realm has nobody requiring administrator MFA")
			}
		})
	}
	accessExec(t, db, ctx, `UPDATE auth.mfa_settings SET mode='optional';
 INSERT INTO auth.roles(key,name,mfa_required) VALUES('future_mfa_role','Future required role',true)`)
	require.Error(t, repo.CheckCapability(ctx, false), "unassigned required role must keep MFA capability")
	require.NoError(t, repo.CheckCapability(ctx, true))
	accessExec(t, db, ctx, `DELETE FROM auth.roles WHERE key='future_mfa_role'`)
	f := newStatusFixture(t, db, ctx, "capability-personal")
	accessExec(t, db, ctx, `INSERT INTO auth.mfa_totp(user_id,secret,last_step) VALUES($1,$2,0)`, f.user, make([]byte, 48))
	require.Error(t, repo.CheckCapability(ctx, false), "optional cannot hide an enrolled personal factor")
	require.NoError(t, repo.CheckCapability(ctx, true))
	accessExec(t, db, ctx, `DELETE FROM auth.mfa_totp WHERE user_id=$1`, f.user)
	require.NoError(t, repo.CheckCapability(ctx, false))
	accessExec(t, db, ctx, `DELETE FROM auth.mfa_settings`)
	require.ErrorIs(t, repo.CheckCapability(ctx, false), settingsdomain.ErrNotInitialized)
	require.ErrorIs(t, repo.CheckCapability(ctx, true), settingsdomain.ErrNotInitialized)
}

func TestOptionalMFALastAdministratorSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	a := newStatusFixture(t, db, ctx, "optional-admin-a")
	b := newStatusFixture(t, db, ctx, "optional-admin-b")
	accessExec(t, db, ctx, `UPDATE auth.mfa_settings SET mode='optional'`)
	accessExec(t, db, ctx, `UPDATE auth.user_emails SET verified_at=clock_timestamp() WHERE user_id=ANY($1::uuid[])`, []string{string(a.user), string(b.user)})
	accessExec(t, db, ctx, `WITH r AS(INSERT INTO auth.roles(key,name,system) VALUES('super_admin','Administrator',true) RETURNING id),
 p AS(INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,'access.assignments.manage' FROM r)
 INSERT INTO auth.user_roles(user_id,role_id) SELECT u.id,r.id FROM auth.users u CROSS JOIN r WHERE u.id=ANY($1::uuid[])`, []string{string(a.user), string(b.user)})
	tx, err := db.Begin(ctx)
	require.NoError(t, err)
	defer func() { require.NoError(t, tx.Rollback(ctx)) }()
	require.NoError(t, accesspostgres.LockAccessChanges(ctx, tx))
	require.NoError(t, accesspostgres.RequireUsableAdministrator(ctx, tx), "optional factorless administrator is usable")
	require.NoError(t, accesspostgres.RequireAdministratorRemains(ctx, tx, a.user), "second optional administrator can remain")
	_, err = tx.Exec(ctx, `UPDATE auth.users SET status='blocked' WHERE id=$1`, b.user)
	require.NoError(t, err)
	require.ErrorIs(t, accesspostgres.RequireAdministratorRemains(ctx, tx, a.user), accountdomain.ErrLastAdministrator)
	_, err = tx.Exec(ctx, `UPDATE auth.user_emails SET verified_at=NULL WHERE user_id=$1`, a.user)
	require.NoError(t, err)
	require.ErrorIs(t, accesspostgres.RequireUsableAdministrator(ctx, tx), accountdomain.ErrLastAdministrator, "optional must retain verified permanent credential requirements")
}
