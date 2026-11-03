package auth_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
)

func TestMFAPolicyFactorRacesSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	actor := accessPrincipal(t, db, ctx)
	accessExec(t, db, ctx, `WITH r AS(INSERT INTO auth.roles(key,name) VALUES('factor_policy_manager','Manager') RETURNING id),
 p AS(INSERT INTO auth.role_permissions(role_id,permission_key)
 SELECT id,unnest(ARRAY['auth.settings.manage','access.roles.manage']) FROM r)
 INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM r`, actor.UserID)
	policies := settingsservice.NewMFA(settingspostgres.New(db), true)
	for _, source := range []string{"realm", "role"} {
		for _, order := range []string{"disable-first", "policy-first", "concurrent"} {
			t.Run(source+"/"+order, func(t *testing.T) {
				// Independent fixtures keep the monotonically increasing policy epoch intact.
				accessExec(t, db, ctx, `UPDATE auth.mfa_settings SET mode='optional'`)
				actor = renewAccessPrincipal(t, db, ctx, actor.UserID)
				f := newStatusFixture(t, db, ctx, source+"-"+order)
				accessExec(t, db, ctx, `INSERT INTO auth.mfa_totp(user_id,secret,last_step) VALUES($1,$2,0)`, f.user, make([]byte, 48))
				session := renewAccessPrincipal(t, db, ctx, f.user)
				proof := mfaservice.Proof{UserID: f.user, TokenHash: session.TokenHash, AuthVersion: 1}
				current, err := policies.Current(ctx)
				require.NoError(t, err)
				tighten := func() error {
					_, err := policies.Update(ctx, settingsservice.MFAUpdateInput{Actor: actor, MFAChange: settingsservice.MFAChange{
						ExpectedVersion: current.Version, Policy: settingsdomain.MFAPolicy{Mode: settingsdomain.MFARequired},
					}})
					return err
				}
				if source == "role" {
					var role accessdomain.RoleID
					key := "factor_" + strings.ReplaceAll(order, "-", "_")
					require.NoError(t, db.QueryRow(ctx, `INSERT INTO auth.roles(key,name) VALUES($1,'Required target') RETURNING id`, key).Scan(&role))
					accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) VALUES($1,$2)`, f.user, role)
					// Assignment changes session role bindings, so obtain the proof afterwards.
					session = renewAccessPrincipal(t, db, ctx, f.user)
					proof.TokenHash = session.TokenHash
					tighten = func() error {
						required := true
						_, err := accesspostgres.NewWithMFA(db, true).UpdateRole(ctx, accessservice.UpdateRoleInput{
							CreateRoleInput: accessservice.CreateRoleInput{Actor: actor, Key: key, Name: "Required target", MFARequired: &required},
							RoleID:          role, ExpectedVersion: 1,
						})
						return err
					}
				}
				disable := func() error { return mfapostgres.New(db).Disable(ctx, proof, mfadomain.CanDisableTOTP) }
				var disableErr, policyErr error
				switch order {
				case "disable-first":
					disableErr = disable()
					policyErr = tighten()
					require.NoError(t, disableErr)
				case "policy-first":
					policyErr = tighten()
					disableErr = disable()
					require.Error(t, disableErr)
				case "concurrent":
					disableErr, policyErr = protectionPair(disable, tighten)
				}
				require.NoError(t, policyErr)
				require.True(t, disableErr == nil || errors.Is(disableErr, mfadomain.ErrProofRequired) || errors.Is(disableErr, mfadomain.ErrRequiredByPolicy), "disable: %v", disableErr)
				var required, enrolled bool
				var version int64
				require.NoError(t, db.QueryRow(ctx, `SELECT auth.mfa_required(id),auth_version,
 EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1) FROM auth.users WHERE id=$1`, f.user).Scan(&required, &version, &enrolled))
				require.True(t, required)
				require.Equal(t, disableErr != nil, enrolled, "only a committed disable may remove the factor")
				if disableErr == nil {
					require.EqualValues(t, 2, version)
				} else {
					require.EqualValues(t, 1, version)
				}
				_, err = f.sessions.FindSession(ctx, proof.TokenHash)
				require.ErrorIs(t, err, sessiondomain.ErrSessionNotFound, "old proof cannot survive either policy tightening or factor removal")
				f.params.AuthVersion = version
				_, err = f.sessions.CreateSession(ctx, f.params)
				require.ErrorIs(t, err, sessiondomain.ErrMFARequired, "neither ordering may grant a factorless session")
			})
		}
	}
}
