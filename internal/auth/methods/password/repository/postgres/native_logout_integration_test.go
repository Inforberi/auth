package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	tokendomain "github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	tokenpostgres "github.com/Inforberi/financial-intelligence/internal/auth/token/repository/postgres"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func assertNativeRevoked(t *testing.T, db *pgxpool.Pool, ctx context.Context, id string, want bool) {
	t.Helper()
	var revoked bool
	if err := db.QueryRow(ctx, `SELECT s.revoked_at IS NOT NULL AND f.revoked_at IS NOT NULL FROM auth.sessions s JOIN auth.refresh_families f ON f.session_id=s.id WHERE s.id=$1`, id).Scan(&revoked); err != nil || revoked != want {
		t.Fatal("wrong API revocation", revoked, err)
	}
}

func checkNativeLogout(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("spent credential logout is own-only and idempotent", func(t *testing.T) {
		svc, binding, current, _ := refreshUseCaseFixture(t, db, ctx)
		next, err := svc.Refresh(ctx, current)
		if err != nil {
			t.Fatal(err)
		}
		_, other, _, _ := refreshUseCaseFixture(t, db, ctx)
		for range 2 {
			if err := svc.Logout(ctx, current); err != nil {
				t.Fatal(err)
			}
		}
		assertNativeRevoked(t, db, ctx, binding.SessionID, true)
		assertNativeRevoked(t, db, ctx, other.SessionID, false)
		if result, err := svc.Refresh(ctx, tokenservice.RefreshInput{Token: next.RefreshToken, IP: current.IP}); result != nil || !errors.Is(err, tokendomain.ErrInvalidRefresh) {
			t.Fatal("logged-out successor accepted", err)
		}
		var events, history int
		if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM auth.refresh_audit WHERE session_id=$1 AND event='logged_out'),(SELECT count(*) FROM auth.refresh_tokens WHERE session_id=$1)`, binding.SessionID).Scan(&events, &history); err != nil || events != 1 || history != 2 {
			t.Fatal("repeated audit or erased reuse history", events, history, err)
		}
		unknown, err := tokengenerate.New().GenerateToken()
		if err != nil {
			t.Fatal(err)
		}
		if err := svc.Logout(ctx, tokenservice.RefreshInput{Token: unknown, IP: current.IP}); err != nil {
			t.Fatal("unknown credential not neutral", err)
		}
	})
	t.Run("owner hint is not authority", func(t *testing.T) {
		_, input, current, _ := refreshUseCaseFixture(t, db, ctx)
		repo := tokenpostgres.New(db)
		verifier, err := tokendomain.RefreshVerifier(current.Token)
		if err != nil {
			t.Fatal(err)
		}
		binding, err := repo.ResolveRefresh(ctx, verifier)
		if err != nil {
			t.Fatal(err)
		}
		binding.SessionID = "22222222-2222-4222-8222-222222222222"
		if err := repo.LogoutRefresh(ctx, binding, verifier); !errors.Is(err, tokendomain.ErrInvalidRefresh) {
			t.Fatal(err)
		}
		assertNativeRevoked(t, db, ctx, input.SessionID, false)
	})
	for _, deferred := range []bool{false, true} {
		t.Run("audit failure rolls back revocation", func(t *testing.T) {
			svc, binding, current, _ := refreshUseCaseFixture(t, db, ctx)
			accessExec(t, db, ctx, `CREATE FUNCTION auth.reject_logout_test() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event='logged_out' THEN RAISE EXCEPTION 'synthetic logout audit failure'; END IF; RETURN NEW; END $$`)
			trigger := `CREATE TRIGGER reject_logout_test BEFORE INSERT ON auth.refresh_audit FOR EACH ROW EXECUTE FUNCTION auth.reject_logout_test()`
			if deferred {
				trigger = `CREATE CONSTRAINT TRIGGER reject_logout_test AFTER INSERT ON auth.refresh_audit DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION auth.reject_logout_test()`
			}
			accessExec(t, db, ctx, trigger)
			defer accessExec(t, db, ctx, `DROP TRIGGER reject_logout_test ON auth.refresh_audit; DROP FUNCTION auth.reject_logout_test()`)
			if err := svc.Logout(ctx, current); err == nil {
				t.Fatal("failed audit/commit claimed logout")
			}
			assertNativeRevoked(t, db, ctx, binding.SessionID, false)
		})
	}
	t.Run("logout and refresh serialize on the family", func(t *testing.T) {
		svc, binding, current, _ := refreshUseCaseFixture(t, db, ctx)
		var wg sync.WaitGroup
		var logoutErr, refreshErr error
		var refreshed *tokenservice.RefreshResult
		wg.Go(func() { logoutErr = svc.Logout(ctx, current) })
		wg.Go(func() { refreshed, refreshErr = svc.Refresh(ctx, current) })
		wg.Wait()
		if logoutErr != nil || refreshErr != nil && !errors.Is(refreshErr, tokendomain.ErrInvalidRefresh) {
			t.Fatal(logoutErr, refreshErr)
		}
		assertNativeRevoked(t, db, ctx, binding.SessionID, true)
		if refreshed != nil {
			if _, err := svc.Refresh(ctx, tokenservice.RefreshInput{Token: refreshed.RefreshToken, IP: current.IP}); !errors.Is(err, tokendomain.ErrInvalidRefresh) {
				t.Fatal("successor survived logout", err)
			}
		}
	})
}
