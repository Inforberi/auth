package postgres

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	tokenpostgres "github.com/Inforberi/financial-intelligence/internal/auth/token/repository/postgres"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func TestMFAPolicyJWTConsumersSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	actor := mfaTokenPolicyActor(t, db, ctx)
	for _, source := range []string{"realm", "role"} {
		for _, enrolled := range []bool{false, true} {
			name := "primary-only"
			if enrolled {
				name = "personal-mfa"
			}
			t.Run(source+"/"+name, func(t *testing.T) {
				updateMFATokenRequirement(t, db, ctx, actor, "", "realm", false)
				tokens, native, keys := nativeIssuanceFixture(t, db, ctx)
				var factor *mfaLoginFixture
				if enrolled {
					f := newMFALoginFixture(t, db, ctx, "jwt-policy-"+source)
					accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,role_id FROM auth.user_roles WHERE user_id=$2`, f.user, native.Proof.UserID)
					native.Proof = f.proof
					factor = &f
				}
				sessions := sessionservice.New(clock.UTCClock{}, sessionpostgres.New(db), tokengenerate.New(), nativePolicyFixture().Sessions)
				code := 0
				login := func() accessservice.Principal {
					t.Helper()
					if enrolled {
						_, err := sessions.BeginLogin(ctx, native.Proof, "", native.IP)
						require.ErrorIs(t, err, sessiondomain.ErrMFARequired, "a primary proof cannot stand in for the enrolled factor")
						input := factor.start(t, ctx)
						input.Code = factor.codes[code]
						code++
						completed, err := factor.login.Complete(ctx, input)
						require.NoError(t, err)
						return accessservice.Principal{UserID: native.Proof.UserID, TokenHash: tokengenerate.New().Hash(completed.Token)}
					}
					created, err := sessions.BeginLogin(ctx, native.Proof, "", native.IP)
					require.NoError(t, err)
					require.Nil(t, created.Challenge)
					return accessservice.Principal{UserID: native.Proof.UserID, TokenHash: tokengenerate.New().Hash(created.RawToken)}
				}
				input := tokenservice.ExchangeInput{Actor: login(), Audience: native.Audience, Scope: native.Scope, IP: native.IP}
				require.NoError(t, db.QueryRow(ctx, `SELECT id FROM auth.sessions WHERE token_hash=$1`, input.Actor.TokenHash).Scan(&input.SessionID))
				result, err := tokens.Exchange(ctx, input)
				require.NoError(t, err)
				verifier, err := authjwt.NewVerifier(authjwt.Expectations{Issuer: "https://auth.example", Audience: "orders", Mode: authjwt.Strict}, keys, time.Now())
				require.NoError(t, err)
				claims, err := verifier.VerifySignature(ctx, result.Raw, time.Now())
				require.NoError(t, err)
				require.Equal(t, enrolled, claims.MFATime != nil)
				methods := []string{"pwd"}
				if enrolled {
					methods = append(methods, "recovery")
				}
				require.Equal(t, methods, claims.Methods)
				repo := tokenpostgres.New(db)
				scope, err := repo.Introspect(ctx, claims, input.Scope)
				require.NoError(t, err)
				require.Equal(t, input.Scope, scope)
				updateMFATokenRequirement(t, db, ctx, actor, native.Proof.UserID, source, true)
				for _, phase := range []string{"tightened", "relaxed"} {
					if phase == "relaxed" {
						updateMFATokenRequirement(t, db, ctx, actor, native.Proof.UserID, source, false)
					}
					denied, err := tokens.Exchange(ctx, input)
					require.ErrorIs(t, err, sessiondomain.ErrSessionNotFound, phase)
					require.Nil(t, denied)
					scope, err := repo.Introspect(ctx, claims, input.Scope)
					require.ErrorIs(t, err, authjwt.ErrInvalidToken, phase)
					require.Empty(t, scope)
					_, err = verifier.VerifySignature(ctx, result.Raw, time.Now())
					require.NoError(t, err, "offline verification has no policy lookup; revocation is bounded by JWT expiry")
				}
				input.Actor = login()
				require.NoError(t, db.QueryRow(ctx, `SELECT id FROM auth.sessions WHERE token_hash=$1`, input.Actor.TokenHash).Scan(&input.SessionID))
				fresh, err := tokens.Exchange(ctx, input)
				require.NoError(t, err)
				freshClaims, err := verifier.VerifySignature(ctx, fresh.Raw, time.Now())
				require.NoError(t, err)
				require.Equal(t, enrolled, freshClaims.MFATime != nil)
				require.Equal(t, methods, freshClaims.Methods)
				_, err = repo.Introspect(ctx, freshClaims, input.Scope)
				require.NoError(t, err)
			})
		}
	}
}
