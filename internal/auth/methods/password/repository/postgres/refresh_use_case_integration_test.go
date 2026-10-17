package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	tokendomain "github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	tokenpostgres "github.com/Inforberi/financial-intelligence/internal/auth/token/repository/postgres"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/signing"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func refreshUseCaseFixture(t *testing.T, db *pgxpool.Pool, ctx context.Context, admin ...bool) (*tokenservice.Service, tokenservice.ExchangeInput, tokenservice.RefreshInput, *authjwt.PublicKeys) {
	t.Helper()
	input, current := refreshFixture(t, db, ctx, admin...)
	raw, err := tokengenerate.New().GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	accessExec(t, db, ctx, `UPDATE auth.refresh_tokens SET token_hash=$2 WHERE token_hash=$1`, current, tokengenerate.New().Hash(raw))
	signer, keys := jwtSigningFixture(t)
	return refreshUseCaseService(t, db, signer), input, tokenservice.RefreshInput{Token: raw, IP: input.IP}, keys
}

func refreshUseCaseService(t *testing.T, db *pgxpool.Pool, signer tokenservice.Signer) *tokenservice.Service {
	t.Helper()
	catalog, err := settings.NewCatalog([]settings.Permission{{Key: "orders.read", Name: "Read"}, {Key: "orders.write", Name: "Write"}})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := tokenservice.New(tokenpostgres.New(db), signer, tokenBudget(func(context.Context, tokenservice.ExchangeInput) error { return nil }), tokengenerate.New(), tokenservice.Config{AccessTTL: 2 * time.Minute, Resources: []tokenservice.Resource{{Audience: "orders", Permissions: []accessdomain.PermissionKey{"orders.read", "orders.write"}}}}, catalog)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func assertRefreshUnconsumed(t *testing.T, db *pgxpool.Pool, ctx context.Context, id string) {
	t.Helper()
	var unchanged bool
	if err := db.QueryRow(ctx, `SELECT f.generation=0 AND f.revoked_at IS NULL
		AND (SELECT count(*) FROM auth.refresh_tokens t WHERE t.session_id=f.session_id AND t.used_at IS NULL)=1
		AND NOT EXISTS(SELECT 1 FROM auth.token_issuance_audit a WHERE a.session_id=f.session_id)
		FROM auth.refresh_families f WHERE f.session_id=$1`, id).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("failed refresh consumed or issued", err)
	}
}

func checkRefreshUseCase(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("signed renewal and committed replay", func(t *testing.T) {
		svc, binding, input, keys := refreshUseCaseFixture(t, db, ctx)
		accessExec(t, db, ctx, `UPDATE auth.sessions SET expires_at=clock_timestamp()+interval '40 seconds' WHERE id=$1`, binding.SessionID)
		var primary, mfa, absolute time.Time
		if err := db.QueryRow(ctx, `SELECT primary_verified_at,mfa_verified_at,absolute_expires_at FROM auth.sessions WHERE id=$1`, binding.SessionID).Scan(&primary, &mfa, &absolute); err != nil {
			t.Fatal(err)
		}
		result, err := svc.Refresh(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		verifier, err := authjwt.NewVerifier(authjwt.Expectations{Issuer: "https://auth.example", Audience: "orders", Mode: authjwt.Strict}, keys, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		claims, err := verifier.VerifySignature(ctx, result.Raw, time.Now())
		if err != nil || claims.Subject != string(binding.Actor.UserID) || claims.SessionID != binding.SessionID || claims.Scope != "orders.read" || claims.AuthTime != primary.Unix() || claims.MFATime == nil || *claims.MFATime != mfa.Unix() || claims.ExpiresAt < time.Now().Add(time.Minute).Unix() || !result.RefreshExpiresAt.Equal(absolute) {
			t.Fatal("wrong refreshed authority", err)
		}
		var preserved bool
		if err := db.QueryRow(ctx, `SELECT primary_verified_at=$2 AND mfa_verified_at=$3 AND absolute_expires_at=$4 AND expires_at>clock_timestamp()+interval '50 minutes' FROM auth.sessions WHERE id=$1`, binding.SessionID, primary, mfa, absolute).Scan(&preserved); err != nil || !preserved {
			t.Fatal("renew/proofs", err)
		}
		if next, err := svc.Refresh(ctx, tokenservice.RefreshInput{Token: result.RefreshToken, IP: input.IP}); next != nil || !errors.Is(err, tokendomain.ErrRefreshEarly) {
			t.Fatal("throttle", err)
		}
		if next, err := svc.Refresh(ctx, input); next != nil || !errors.Is(err, tokendomain.ErrInvalidRefresh) {
			t.Fatal("replay", err)
		}
		var revoked bool
		if err := db.QueryRow(ctx, `SELECT s.revoked_at IS NOT NULL AND f.revoked_at IS NOT NULL AND EXISTS(SELECT 1 FROM auth.refresh_audit WHERE session_id=s.id AND event='reuse_detected') FROM auth.sessions s JOIN auth.refresh_families f ON f.session_id=s.id WHERE s.id=$1`, binding.SessionID).Scan(&revoked); err != nil || !revoked {
			t.Fatal("denial rolled back revoke", err)
		}
		if next, err := svc.Refresh(ctx, tokenservice.RefreshInput{Token: result.RefreshToken, IP: input.IP}); next != nil || !errors.Is(err, tokendomain.ErrInvalidRefresh) {
			t.Fatal("successor survived reuse", err)
		}
	})

	t.Run("concurrent owner commits replay", func(t *testing.T) {
		svc, binding, input, _ := refreshUseCaseFixture(t, db, ctx)
		var wg sync.WaitGroup
		outcomes := make(chan error, 2)
		for range 2 {
			wg.Go(func() { _, err := svc.Refresh(ctx, input); outcomes <- err })
		}
		wg.Wait()
		close(outcomes)
		accepted, replayed := 0, 0
		for err := range outcomes {
			switch {
			case err == nil:
				accepted++
			case errors.Is(err, tokendomain.ErrInvalidRefresh):
				replayed++
			default:
				t.Fatal(err)
			}
		}
		if accepted != 1 || replayed != 1 {
			t.Fatal("not one successor", accepted, replayed)
		}
		var count int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.token_issuance_audit WHERE session_id=$1`, binding.SessionID).Scan(&count); err != nil || count != 1 {
			t.Fatal("extra issuance", count, err)
		}
	})

	for _, test := range []struct {
		name, query string
		want        error
	}{
		{"blocked", `UPDATE auth.users SET status='blocked' WHERE id=$1`, tokendomain.ErrInvalidRefresh},
		{"version", `UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`, tokendomain.ErrInvalidRefresh},
		{"logout", `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE user_id=$1`, tokendomain.ErrInvalidRefresh},
		{"expired", `UPDATE auth.sessions SET expires_at=created_at+interval '1 microsecond' WHERE user_id=$1`, tokendomain.ErrInvalidRefresh},
		{"role revision", `UPDATE auth.roles SET session_revision=session_revision+1 WHERE id IN(SELECT role_id FROM auth.user_roles WHERE user_id=$1)`, tokendomain.ErrInvalidRefresh},
		{"no grants", `DELETE FROM auth.role_permissions WHERE role_id IN(SELECT role_id FROM auth.user_roles WHERE user_id=$1)`, tokendomain.ErrForbidden},
		{"MFA missing", `UPDATE auth.sessions SET mfa_verified_at=NULL WHERE user_id=$1`, sessiondomain.ErrMFARequired},
		{"factor removed", `DELETE FROM auth.mfa_totp WHERE user_id=$1`, sessiondomain.ErrMFARequired},
		{"activation pending", `INSERT INTO auth.account_provisions(actor_id,request_key,fingerprint,user_id) VALUES($1,gen_random_uuid(),repeat('a',64),$1)`, sessiondomain.ErrSessionNotFound},
		{"password change pending", `INSERT INTO auth.account_provisions(actor_id,request_key,fingerprint,user_id,activated_at,password_change_required) VALUES($1,gen_random_uuid(),repeat('a',64),$1,clock_timestamp(),true)`, sessiondomain.ErrSessionNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			svc, binding, input, _ := refreshUseCaseFixture(t, db, ctx)
			accessExec(t, db, ctx, test.query, binding.Actor.UserID)
			if result, err := svc.Refresh(ctx, input); result != nil || !errors.Is(err, test.want) {
				t.Fatal(result, err)
			}
			assertRefreshUnconsumed(t, db, ctx, binding.SessionID)
		})
	}
	checkRefreshFailures(t, db, ctx)
}

// A failing local signer never exposes credentials or consumes the refresh token.
type failingRefreshSigner struct{}

func (failingRefreshSigner) Sign(context.Context, authjwt.Claims, time.Time) (*signing.SignedToken, error) {
	return nil, authjwt.ErrBusy
}
