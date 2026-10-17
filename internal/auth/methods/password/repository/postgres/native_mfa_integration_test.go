package postgres

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type nativeMFAFixture struct {
	mfaLoginFixture
	coordinator *tokenservice.NativeLogin
	tokens      *tokenservice.Service
	input       mfaservice.CompleteLoginInput
	keys        *authjwt.PublicKeys
}

func newNativeMFAFixture(t *testing.T, db *pgxpool.Pool, ctx context.Context, name string) nativeMFAFixture {
	t.Helper()
	f := newMFALoginFixture(t, db, ctx, "native-"+name)
	var role string
	if err := db.QueryRow(ctx, `INSERT INTO auth.roles(key,name,mfa_required) VALUES($1,'Native MFA fixture',true) RETURNING id`, "native_"+strings.ReplaceAll(string(f.user), "-", "")).Scan(&role); err != nil {
		t.Fatal(err)
	}
	accessExec(t, db, ctx, `INSERT INTO auth.role_permissions(role_id,permission_key) VALUES($1,'orders.read'),($1,'orders.write')`, role)
	accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) VALUES($1,$2)`, f.user, role)
	signer, keys := jwtSigningFixture(t)
	tokens := nativeTokenService(t, db, signer)
	coordinator, err := tokenservice.NewNativeLogin(tokens, f.login)
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.Begin(ctx, tokenservice.NativeInput{Proof: f.proof, Audience: "orders", Scope: []accessdomain.PermissionKey{"orders.read"}, IP: "192.0.2.1", UserAgent: "native MFA fixture"})
	if err != nil || result == nil || result.Challenge == nil || result.Tokens != nil || result.Challenge.EnrollmentRequired {
		t.Fatal("invalid restricted result", err)
	}
	input := mfaservice.CompleteLoginInput{Token: result.Challenge.Token, Binding: result.Challenge.Binding, Code: f.codes[0], Recovery: true, IP: "192.0.2.1", UserAgent: "native MFA fixture"}
	return nativeMFAFixture{mfaLoginFixture: f, coordinator: coordinator, tokens: tokens, input: input, keys: keys}
}

func assertNativeMFARows(t *testing.T, db *pgxpool.Pool, ctx context.Context, f nativeMFAFixture, want int) {
	t.Helper()
	for _, query := range []string{
		`SELECT count(*) FROM auth.sessions WHERE user_id=$1 AND credential_profile='api'`,
		`SELECT count(*) FROM auth.refresh_families f JOIN auth.sessions s ON s.id=f.session_id WHERE s.user_id=$1`,
		`SELECT count(*) FROM auth.token_issuance_audit WHERE user_id=$1`,
	} {
		var count int
		if err := db.QueryRow(ctx, query, f.user).Scan(&count); err != nil || count != want {
			t.Fatal("native MFA transaction state", want, count, err)
		}
	}
}

func checkNativeMFA(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	for _, recovery := range []bool{true, false} {
		name := "totp"
		if recovery {
			name = "recovery"
		}
		t.Run(name+" atomic parallel completion", func(t *testing.T) {
			f := newNativeMFAFixture(t, db, ctx, name)
			f.input.Recovery = recovery
			if !recovery {
				f.input.Code = mfaCode(t, db, ctx, f.secret, 30*time.Second)
			}
			var wg sync.WaitGroup
			results := make(chan *tokenservice.RefreshResult, 8)
			failures := make(chan error, 8)
			for range 8 {
				wg.Go(func() { result, err := f.coordinator.Complete(ctx, f.input); results <- result; failures <- err })
			}
			wg.Wait()
			close(results)
			close(failures)
			for err := range failures {
				if err != nil && !errors.Is(err, mfadomain.ErrInvalidCode) {
					t.Fatal(err)
				}
			}
			var winner *tokenservice.RefreshResult
			count := 0
			for result := range results {
				if result != nil {
					count++
					winner = result
				}
			}
			if count != 1 {
				t.Fatal("not one committed winner", count)
			}
			assertNativeMFARows(t, db, ctx, f, 1)
			verify, err := authjwt.NewVerifier(authjwt.Expectations{Issuer: "https://auth.example", Audience: "orders", Mode: authjwt.Strict}, f.keys, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			claims, err := verify.VerifySignature(ctx, winner.Raw, time.Now())
			if err != nil || claims.Subject != string(f.user) || claims.AuthVersion != 2 || claims.Scope != "orders.read" || claims.MFATime == nil || *claims.MFATime < claims.AuthTime || len(claims.Methods) != 2 || claims.Methods[1] != "mfa" {
				t.Fatal("incorrect MFA claims", err)
			}
			var privateProof, challenge bool
			if err := db.QueryRow(ctx, `SELECT password_verified_at IS NOT NULL,EXISTS(SELECT 1 FROM auth.mfa_login_challenges WHERE user_id=$2) FROM auth.sessions WHERE id=$1`, claims.SessionID, f.user).Scan(&privateProof, &challenge); err != nil || privateProof || challenge {
				t.Fatal("false private proof or reusable challenge", err)
			}
			if _, err := f.tokens.Refresh(ctx, tokenservice.RefreshInput{Token: winner.RefreshToken, IP: f.input.IP}); err != nil {
				t.Fatal("completed MFA family cannot refresh", err)
			}
		})
	}
	checkNativeMFAGuards(t, db, ctx)
	checkNativeMFAFailures(t, db, ctx)
	checkNativeMFAEnrollment(t, db, ctx)
}
