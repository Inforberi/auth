package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	tokendomain "github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	tokenpostgres "github.com/Inforberi/financial-intelligence/internal/auth/token/repository/postgres"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func nativePolicyFixture() tokenservice.NativePolicy {
	return tokenservice.NativePolicy{IdleTTL: time.Hour, AbsoluteTTL: 2 * time.Hour, Sessions: sessionservice.Config{SessionTTL: 7 * 24 * time.Hour, AbsoluteSessionTTL: 14 * 24 * time.Hour, AdminIdleTimeout: 30 * time.Minute, AdminAbsoluteTTL: 12 * time.Hour, AdminActivityInterval: time.Minute}}
}

func nativeTokenService(t *testing.T, db *pgxpool.Pool, signer tokenservice.Signer) *tokenservice.Service {
	t.Helper()
	catalog, err := settings.NewCatalog([]settings.Permission{{Key: "orders.read", Name: "Read"}, {Key: "orders.write", Name: "Write"}})
	if err != nil {
		t.Fatal(err)
	}
	policy := nativePolicyFixture()
	svc, err := tokenservice.New(tokenpostgres.New(db), signer, tokenBudget(func(context.Context, tokenservice.ExchangeInput) error { return nil }), tokengenerate.New(), tokenservice.Config{AccessTTL: 2 * time.Minute, Native: &policy, Resources: []tokenservice.Resource{{Audience: "orders", Permissions: []accessdomain.PermissionKey{"orders.read", "orders.write"}}}}, catalog)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func nativeIssuanceFixture(t *testing.T, db *pgxpool.Pool, ctx context.Context) (*tokenservice.Service, tokenservice.NativeInput, *authjwt.PublicKeys) {
	t.Helper()
	label, err := tokengenerate.New().GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	email := "native-" + strings.ToLower(label) + "@example.test"
	legacy := hasher.NewArgon2idHash(1, 16, 1024, 1, 32)
	hash, err := legacy.GenerateHash([]byte("Password12345"))
	if err != nil {
		t.Fatal(err)
	}
	passwords := New(db)
	user, err := passwords.CreateUser(ctx, email, hash)
	if err != nil {
		t.Fatal(err)
	}
	var role string
	if err := db.QueryRow(ctx, `INSERT INTO auth.roles(key,name,mfa_required) VALUES($1,'Native fixture',false) RETURNING id`, "native_"+strings.ReplaceAll(string(user), "-", "")).Scan(&role); err != nil {
		t.Fatal(err)
	}
	accessExec(t, db, ctx, `INSERT INTO auth.role_permissions(role_id,permission_key) VALUES($1,'orders.read'),($1,'orders.write')`, role)
	accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) VALUES($1,$2)`, user, role)
	bounded := hasher.NewBounded(hasher.NewArgon2idHash(2, 16, 1024, 1, 32), 2)
	primary := passwordservice.New(passwords, nil, bounded, loginTestLimit{})
	proof, err := primary.Authenticate(ctx, passwordservice.LoginInput{Email: email, Password: "Password12345", IP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	if proof.Reference == hash {
		t.Fatal("native proof lost rehash")
	}
	assertNativeRows(t, db, ctx, string(user), 0)
	signer, keys := jwtSigningFixture(t)
	return nativeTokenService(t, db, signer), tokenservice.NativeInput{Proof: proof, Audience: "orders", Scope: []accessdomain.PermissionKey{"orders.read"}, IP: "192.0.2.1", UserAgent: "native fixture"}, keys
}

func assertNativeRows(t *testing.T, db *pgxpool.Pool, ctx context.Context, user string, want int) {
	t.Helper()
	for _, query := range []string{
		`SELECT count(*) FROM auth.sessions WHERE user_id=$1`,
		`SELECT count(*) FROM auth.refresh_families f JOIN auth.sessions s ON s.id=f.session_id WHERE s.user_id=$1`,
		`SELECT count(*) FROM auth.refresh_tokens t JOIN auth.sessions s ON s.id=t.session_id WHERE s.user_id=$1`,
		`SELECT count(*) FROM auth.token_issuance_audit WHERE user_id=$1`,
		`SELECT count(*) FROM auth.refresh_audit WHERE user_id=$1`,
	} {
		var count int
		if err := db.QueryRow(ctx, query, user).Scan(&count); err != nil || count != want {
			t.Fatal("non-atomic native issuance", want, count, err)
		}
	}
}

func checkNativeIssuance(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("password proof to API ledger and refresh", func(t *testing.T) {
		svc, input, keys := nativeIssuanceFixture(t, db, ctx)
		result, err := svc.IssueNative(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		assertNativeRows(t, db, ctx, string(input.Proof.UserID), 1)
		verify, err := authjwt.NewVerifier(authjwt.Expectations{Issuer: "https://auth.example", Audience: "orders", Mode: authjwt.Strict}, keys, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		claims, err := verify.VerifySignature(ctx, result.Raw, time.Now())
		if err != nil || claims.Subject != string(input.Proof.UserID) || claims.Scope != "orders.read" || claims.AuthVersion != 1 || claims.MFATime != nil || len(claims.Methods) != 1 || claims.Methods[0] != "pwd" {
			t.Fatal("wrong primary claims", err)
		}
		var ledger string
		var isolated bool
		if err := db.QueryRow(ctx, `SELECT s.token_hash,s.credential_profile='api' AND s.mfa_verified_at IS NULL AND s.password_verified_at IS NULL
			AND s.absolute_expires_at=s.created_at+interval '2 hours' AND s.expires_at=s.created_at+interval '1 hour'
			AND t.token_hash<>s.token_hash AND f.audience='orders' AND f.scope=ARRAY['orders.read']::text[]
			FROM auth.sessions s JOIN auth.refresh_families f ON f.session_id=s.id JOIN auth.refresh_tokens t ON t.session_id=s.id WHERE s.id=$1`, claims.SessionID).Scan(&ledger, &isolated); err != nil || !isolated {
			t.Fatal("ledger/refresh/assurance/lifetime binding", err)
		}
		if _, err := sessionpostgres.New(db).FindSession(ctx, ledger); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
			t.Fatal("API ledger accepted as browser cookie", err)
		}
		renewed, err := svc.Refresh(ctx, tokenservice.RefreshInput{Token: result.RefreshToken, IP: input.IP})
		if err != nil || renewed.RefreshToken == result.RefreshToken || !renewed.RefreshExpiresAt.Equal(result.RefreshExpiresAt) {
			t.Fatal("new family cannot refresh", err)
		}
	})
	for _, test := range []struct {
		name, query string
		want        error
	}{
		{"block", `UPDATE auth.users SET status='blocked' WHERE id=$1`, mfadomain.ErrProofRequired},
		{"version", `UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`, mfadomain.ErrProofRequired},
		{"reference replaced", `UPDATE auth.password_credentials SET password_hash='changed after primary' WHERE user_id=$1`, mfadomain.ErrProofRequired},
		{"grant revoked", `DELETE FROM auth.role_permissions WHERE role_id IN(SELECT role_id FROM auth.user_roles WHERE user_id=$1)`, tokendomain.ErrForbidden},
		{"MFA enrolled", `INSERT INTO auth.mfa_totp(user_id,secret,last_step) VALUES($1,decode(repeat('ab',48),'hex'),0)`, sessiondomain.ErrMFARequired},
		{"role requires MFA", `UPDATE auth.roles SET mfa_required=true WHERE id IN(SELECT role_id FROM auth.user_roles WHERE user_id=$1)`, sessiondomain.ErrMFARequired},
		{"activation pending", `INSERT INTO auth.account_provisions(actor_id,request_key,fingerprint,user_id) VALUES($1,gen_random_uuid(),repeat('a',64),$1)`, sessiondomain.ErrSessionNotFound},
		{"temporary completion pending", `INSERT INTO auth.account_provisions(actor_id,request_key,fingerprint,user_id,activated_at,password_change_required) VALUES($1,gen_random_uuid(),repeat('a',64),$1,clock_timestamp(),true)`, sessiondomain.ErrSessionNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			svc, input, _ := nativeIssuanceFixture(t, db, ctx)
			accessExec(t, db, ctx, test.query, input.Proof.UserID)
			if result, err := svc.IssueNative(ctx, input); result != nil || !errors.Is(err, test.want) {
				t.Fatal("stale primary issued", err)
			}
			assertNativeRows(t, db, ctx, string(input.Proof.UserID), 0)
		})
	}
	checkNativeIssuanceFailures(t, db, ctx)
}
