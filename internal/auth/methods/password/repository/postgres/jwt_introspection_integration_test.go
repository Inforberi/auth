package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	tokenpostgres "github.com/Inforberi/financial-intelligence/internal/auth/token/repository/postgres"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func checkJWTIntrospection(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	repo := tokenpostgres.New(db)
	fixture := func(t *testing.T) authjwt.Claims {
		t.Helper()
		signer, keys := jwtSigningFixture(t)
		svc := nativeTokenService(t, db, signer)
		input := jwtActor(t, db, ctx)
		result, err := svc.Exchange(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		v, err := authjwt.NewVerifier(authjwt.Expectations{Issuer: "https://auth.example", Audience: "orders", Mode: authjwt.Strict}, keys, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		claims, err := v.VerifySignature(ctx, result.Raw, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return claims
	}
	read := []accessdomain.PermissionKey{"orders.read"}
	t.Run("live snapshot read only and scope does not grow", func(t *testing.T) {
		claims := fixture(t)
		var before string
		const snapshot = `SELECT row_to_json(s)::text FROM auth.sessions s WHERE id=$1`
		if err := db.QueryRow(ctx, snapshot, claims.SessionID).Scan(&before); err != nil {
			t.Fatal(err)
		}
		for range 3 {
			scope, err := repo.Introspect(ctx, claims, read)
			if err != nil || !slices.Equal(scope, read) {
				t.Fatal(scope, err)
			}
		}
		var after string
		if err := db.QueryRow(ctx, snapshot, claims.SessionID).Scan(&after); err != nil || before != after {
			t.Fatal("introspection mutated ledger", err)
		}
		other := accessPrincipal(t, db, ctx)
		for name, mutate := range map[string]func(*authjwt.Claims){
			"user":                   func(c *authjwt.Claims) { c.Subject = string(other.UserID) },
			"version":                func(c *authjwt.Claims) { c.AuthVersion++ },
			"primary proof":          func(c *authjwt.Claims) { c.AuthTime-- },
			"mfa proof":              func(c *authjwt.Claims) { v := *c.MFATime - 1; c.MFATime = &v },
			"expiry exceeds session": func(c *authjwt.Claims) { c.ExpiresAt = time.Now().Add(30 * 24 * time.Hour).Unix() },
		} {
			t.Run(name, func(t *testing.T) {
				c := claims
				mutate(&c)
				if _, err := repo.Introspect(ctx, c, read); !errors.Is(err, authjwt.ErrInvalidToken) {
					t.Fatal("binding accepted", err)
				}
			})
		}
	})
	for _, tc := range []struct{ name, query string }{
		{"logout", `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE user_id=$1`},
		{"reset version", `UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`},
		{"blocked", `UPDATE auth.users SET status='blocked' WHERE id=$1`},
		{"deleted", `UPDATE auth.users SET deleted_at=clock_timestamp(),status='blocked' WHERE id=$1`},
		{"MFA removed", `DELETE FROM auth.mfa_totp WHERE user_id=$1`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := fixture(t)
			accessExec(t, db, ctx, tc.query, claims.Subject)
			if _, err := repo.Introspect(ctx, claims, read); !errors.Is(err, authjwt.ErrInvalidToken) {
				t.Fatal("inactive accepted", err)
			}
		})
	}
	t.Run("current grants intersection", func(t *testing.T) {
		claims := fixture(t)
		accessExec(t, db, ctx, `DELETE FROM auth.role_permissions WHERE permission_key='orders.read' AND role_id IN(SELECT role_id FROM auth.user_roles WHERE user_id=$1)`, claims.Subject)
		scope, err := repo.Introspect(ctx, claims, read)
		// Revision-bound session invalidation is also a valid stronger denial after a role mutation.
		if len(scope) != 0 || err != nil && !errors.Is(err, authjwt.ErrInvalidToken) {
			t.Fatal("removed grant accepted", scope, err)
		}
	})
	t.Run("concurrent revoke wins before snapshot", func(t *testing.T) {
		claims := fixture(t)
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE id=$1`, claims.SessionID); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { _, err := repo.Introspect(ctx, claims, read); done <- err }()
		waitJWTSQLLock(t, db, ctx)
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-done; !errors.Is(err, authjwt.ErrInvalidToken) {
			t.Fatal("revoke race", err)
		}
	})
	t.Run("API family independently revoked", func(t *testing.T) {
		svc, input, keys := nativeIssuanceFixture(t, db, ctx)
		result, err := svc.IssueNative(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		v, err := authjwt.NewVerifier(authjwt.Expectations{Issuer: "https://auth.example", Audience: "orders", Mode: authjwt.Strict}, keys, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		claims, err := v.VerifySignature(ctx, result.Raw, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if scope, err := repo.Introspect(ctx, claims, read); err != nil || !slices.Equal(scope, read) {
			t.Fatal(scope, err)
		}
		accessExec(t, db, ctx, `UPDATE auth.refresh_families SET revoked_at=clock_timestamp() WHERE session_id=$1`, claims.SessionID)
		if _, err := repo.Introspect(ctx, claims, read); !errors.Is(err, authjwt.ErrInvalidToken) {
			t.Fatal("revoked family accepted", err)
		}
	})
	checkIntrospectionHTTP(t, db, ctx)
}

func introspectionCredential() (string, string) {
	secret := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	hash := sha256.Sum256([]byte(secret))
	return secret, hex.EncodeToString(hash[:])
}
