package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	tokendomain "github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	tokenpostgres "github.com/Inforberi/financial-intelligence/internal/auth/token/repository/postgres"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func TestMFAPolicyNativeSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	actor := mfaTokenPolicyActor(t, db, ctx)
	for _, source := range []string{"realm", "role"} {
		for _, primary := range []string{"password", "emailotp"} {
			t.Run(source+"/"+primary, func(t *testing.T) {
				updateMFATokenRequirement(t, db, ctx, actor, "", "realm", false)
				f := newNativeEmailFixture(t, db, ctx)
				passwords := passwordservice.New(New(db), nil, hasher.NewBounded(hasher.NewArgon2idHash(2, 16, 1024, 1, 32), 2), loginTestLimit{})
				begin := func() *tokenservice.NativeLoginResult {
					t.Helper()
					if primary == "emailotp" {
						result, err := f.login.Confirm(ctx, f.request(t, db, ctx))
						require.NoError(t, err)
						return result
					}
					proof, err := passwords.Authenticate(ctx, passwordservice.LoginInput{Email: f.email, Password: "Password12345", IP: "192.0.2.1"})
					require.NoError(t, err)
					result, err := f.primary.Begin(ctx, tokenservice.NativeInput{Proof: proof, Audience: "orders", Scope: []accessdomain.PermissionKey{"orders.read"}, IP: "192.0.2.1"})
					require.NoError(t, err)
					return result
				}
				verifier, err := authjwt.NewVerifier(authjwt.Expectations{Issuer: "https://auth.example", Audience: "orders", Mode: authjwt.Strict}, f.keys, time.Now())
				require.NoError(t, err)
				verify := func(result *tokenservice.RefreshResult, mfa bool) {
					t.Helper()
					require.NotNil(t, result)
					claims, err := verifier.VerifySignature(ctx, result.Raw, time.Now())
					require.NoError(t, err)
					methods := []string{"pwd"}
					if primary == "emailotp" {
						methods[0] = "emailotp"
					}
					if mfa {
						methods = append(methods, "recovery")
					}
					require.Equal(t, methods, claims.Methods)
					require.Equal(t, mfa, claims.MFATime != nil)
					if mfa {
						require.GreaterOrEqual(t, *claims.MFATime, claims.AuthTime)
					}
					require.Equal(t, string(f.user), claims.Subject)
					scope, err := tokenpostgres.New(db).Introspect(ctx, claims, []accessdomain.PermissionKey{"orders.read"})
					require.NoError(t, err)
					require.Equal(t, []accessdomain.PermissionKey{"orders.read"}, scope)
				}
				optional := begin()
				require.Nil(t, optional.Challenge)
				verify(optional.Tokens, false)
				oldClaims, err := verifier.VerifySignature(ctx, optional.Tokens.Raw, time.Now())
				require.NoError(t, err)
				updateMFATokenRequirement(t, db, ctx, actor, f.user, source, true)
				_, err = tokenpostgres.New(db).Introspect(ctx, oldClaims, []accessdomain.PermissionKey{"orders.read"})
				require.ErrorIs(t, err, authjwt.ErrInvalidToken)
				oldRefresh := tokenservice.RefreshInput{Token: optional.Tokens.RefreshToken, IP: "192.0.2.1"}
				denied, err := f.tokens.Refresh(ctx, oldRefresh)
				require.ErrorIs(t, err, tokendomain.ErrInvalidRefresh)
				require.Nil(t, denied)
				limited := begin()
				require.Nil(t, limited.Tokens)
				require.NotNil(t, limited.Challenge)
				require.True(t, limited.Challenge.EnrollmentRequired)
				bound := mfaservice.LoginEnrollmentInput{Challenge: limited.Challenge.Token, Binding: limited.Challenge.Binding, IP: "192.0.2.1"}
				enrollment, err := f.mfa.StartNativeRequiredEnrollment(ctx, bound)
				require.NoError(t, err)
				codes, err := f.mfa.ConfirmNativeRequiredEnrollment(ctx, mfaservice.ConfirmLoginEnrollmentInput{
					LoginEnrollmentInput: bound, Token: enrollment.Token, Code: mfaCode(t, db, ctx, enrollment.Secret, 0),
				})
				require.NoError(t, err)
				require.Len(t, codes.Codes, 10)
				var sessions int
				require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.sessions WHERE user_id=$1 AND credential_profile='api'`, f.user).Scan(&sessions))
				require.Equal(t, 1, sessions, "enrollment must not issue another native session")
				complete := func(code string) *tokenservice.RefreshResult {
					t.Helper()
					pending := begin()
					require.Nil(t, pending.Tokens)
					require.NotNil(t, pending.Challenge)
					require.False(t, pending.Challenge.EnrollmentRequired)
					result, err := f.primary.Complete(ctx, mfaservice.CompleteLoginInput{
						Token: pending.Challenge.Token, Binding: pending.Challenge.Binding, Code: code, Recovery: true, IP: "192.0.2.1",
					})
					require.NoError(t, err)
					verify(result, true)
					return result
				}
				strong := complete(codes.Codes[0])
				updateMFATokenRequirement(t, db, ctx, actor, f.user, source, false)
				_, err = tokenpostgres.New(db).Introspect(ctx, oldClaims, []accessdomain.PermissionKey{"orders.read"})
				require.ErrorIs(t, err, authjwt.ErrInvalidToken, "relaxation must not revive native JWT authority")
				denied, err = f.tokens.Refresh(ctx, oldRefresh)
				require.ErrorIs(t, err, tokendomain.ErrInvalidRefresh, "relaxation must not revive the old family")
				require.Nil(t, denied)
				complete(codes.Codes[1])
				refreshed, err := f.tokens.Refresh(ctx, tokenservice.RefreshInput{Token: strong.RefreshToken, IP: "192.0.2.1"})
				require.NoError(t, err)
				verify(refreshed, true)
			})
		}
	}
}

func mfaTokenPolicyActor(t *testing.T, db *pgxpool.Pool, ctx context.Context) accessservice.Principal {
	t.Helper()
	actor := accessPrincipal(t, db, ctx)
	accessExec(t, db, ctx, `WITH r AS(INSERT INTO auth.roles(key,name) VALUES('token_policy_manager','Manager') RETURNING id),
 p AS(INSERT INTO auth.role_permissions(role_id,permission_key)
 SELECT id,unnest(ARRAY['auth.settings.manage','access.roles.manage','orders.read','orders.write']) FROM r)
 INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM r`, actor.UserID)
	return actor
}

func updateMFATokenRequirement(t *testing.T, db *pgxpool.Pool, ctx context.Context, actor accessservice.Principal, user accountdomain.UserID, source string, required bool) {
	t.Helper()
	actor = renewAccessPrincipal(t, db, ctx, actor.UserID)
	if source == "realm" {
		svc := settingsservice.NewMFA(settingspostgres.New(db), true)
		current, err := svc.Current(ctx)
		require.NoError(t, err)
		mode := settingsdomain.MFAOptional
		if required {
			mode = settingsdomain.MFARequired
		}
		_, err = svc.Update(ctx, settingsservice.MFAUpdateInput{Actor: actor, MFAChange: settingsservice.MFAChange{ExpectedVersion: current.Version, Policy: settingsdomain.MFAPolicy{Mode: mode}}})
		require.NoError(t, err)
		return
	}
	var role accessdomain.Role
	require.NoError(t, db.QueryRow(ctx, `SELECT r.id,r.key,r.name,r.version FROM auth.roles r JOIN auth.user_roles ur ON ur.role_id=r.id WHERE ur.user_id=$1`, user).Scan(&role.ID, &role.Key, &role.Name, &role.Version))
	_, err := accesspostgres.NewWithMFA(db, true).UpdateRole(ctx, accessservice.UpdateRoleInput{
		CreateRoleInput: accessservice.CreateRoleInput{Actor: actor, Key: role.Key, Name: role.Name, Permissions: []accessdomain.PermissionKey{"orders.read", "orders.write"}, MFARequired: &required},
		RoleID:          role.ID, ExpectedVersion: role.Version,
	})
	require.NoError(t, err)
}
