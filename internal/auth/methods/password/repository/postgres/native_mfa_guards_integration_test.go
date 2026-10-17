package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	tokendomain "github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	tokenpostgres "github.com/Inforberi/financial-intelligence/internal/auth/token/repository/postgres"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

func checkNativeMFAGuards(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("profile confusion and immutable target", func(t *testing.T) {
		f := newNativeMFAFixture(t, db, ctx, "profile")
		if result, err := f.login.Complete(ctx, f.input); result != nil || !errors.Is(err, mfadomain.ErrInvalidCode) {
			t.Fatal("browser accepted native challenge", err)
		}
		cipher, err := secretbox.NewScoped(base64.StdEncoding.EncodeToString(make([]byte, 32)), "mfa:v1")
		if err != nil {
			t.Fatal(err)
		}
		digest, binding := cipher.Digest("native-login:"+f.input.Token), cipher.Digest("native-binding:"+f.input.Binding)
		if _, err := mfapostgres.New(db).CompleteLogin(ctx, mfaservice.LoginCompletion{Digest: digest, BindingHash: binding}, nil); !errors.Is(err, mfadomain.ErrInvalidCode) {
			t.Fatal("browser SQL accepted native profile", err)
		}
		for _, query := range []string{`UPDATE auth.mfa_login_challenges SET native_audience='other' WHERE user_id=$1`, `UPDATE auth.mfa_login_challenges SET native_scope=ARRAY['orders.write'] WHERE user_id=$1`, `UPDATE auth.mfa_login_challenges SET credential_profile='browser',native_scope=NULL,native_audience=NULL WHERE user_id=$1`} {
			expectSQLState(t, db, ctx, "P0001", query, f.user)
		}
		browser, err := f.login.Start(ctx, f.proof, f.input.IP)
		if err != nil {
			t.Fatal(err)
		}
		input := f.input
		input.Token, input.Binding = browser.Token, browser.Binding
		if result, err := f.coordinator.Complete(ctx, input); result != nil || !errors.Is(err, mfadomain.ErrInvalidCode) {
			t.Fatal("native accepted browser challenge", err)
		}
		attempt := mfaservice.NativeAttempt{UserID: f.user, Digest: cipher.Digest("login:" + browser.Token), BindingHash: cipher.Digest("browser:" + browser.Binding)}
		if result, err := tokenpostgres.New(db).CompleteNativeMFA(ctx, tokenservice.NativeMFAParams{Attempt: attempt}, nil, nil); result != nil || !errors.Is(err, mfadomain.ErrInvalidCode) {
			t.Fatal("native SQL accepted browser profile", err)
		}
		assertNativeMFARows(t, db, ctx, f, 0)
	})
	t.Run("wrong binding and five committed attempts", func(t *testing.T) {
		f := newNativeMFAFixture(t, db, ctx, "attempts")
		wrong := f.input
		wrong.Binding = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		if _, err := f.coordinator.Complete(ctx, wrong); !errors.Is(err, mfadomain.ErrInvalidCode) {
			t.Fatal(err)
		}
		var attempts int
		if err := db.QueryRow(ctx, `SELECT attempts FROM auth.mfa_login_challenges WHERE user_id=$1`, f.user).Scan(&attempts); err != nil || attempts != 0 {
			t.Fatal("wrong binding burned attempts", err)
		}
		wrong = f.input
		wrong.Code = "00000000000000000000000000000000"
		for range 5 {
			if _, err := f.coordinator.Complete(ctx, wrong); !errors.Is(err, mfadomain.ErrInvalidCode) {
				t.Fatal(err)
			}
		}
		if err := db.QueryRow(ctx, `SELECT attempts FROM auth.mfa_login_challenges WHERE user_id=$1`, f.user).Scan(&attempts); err != nil || attempts != 5 {
			t.Fatal("failed attempts rolled back", attempts, err)
		}
		if _, err := f.coordinator.Complete(ctx, f.input); !errors.Is(err, mfadomain.ErrInvalidCode) {
			t.Fatal("exhausted challenge accepted", err)
		}
		assertNativeMFARows(t, db, ctx, f, 0)
	})
	for _, test := range []struct {
		name, query string
		want        error
	}{
		{"block", `UPDATE auth.users SET status='blocked' WHERE id=$1`, mfadomain.ErrInvalidCode},
		{"version", `UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`, mfadomain.ErrInvalidCode},
		{"reference", `UPDATE auth.password_credentials SET password_hash='replacement' WHERE user_id=$1`, mfadomain.ErrInvalidCode},
		{"grants", `DELETE FROM auth.role_permissions WHERE role_id IN(SELECT role_id FROM auth.user_roles WHERE user_id=$1)`, tokendomain.ErrForbidden},
		{"expired", `UPDATE auth.mfa_login_challenges SET expires_at=created_at+interval '1 microsecond' WHERE user_id=$1`, mfadomain.ErrInvalidCode},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newNativeMFAFixture(t, db, ctx, test.name)
			accessExec(t, db, ctx, test.query, f.user)
			if result, err := f.coordinator.Complete(ctx, f.input); result != nil || !errors.Is(err, test.want) {
				t.Fatal("stale native completion", err)
			}
			assertNativeMFARows(t, db, ctx, f, 0)
		})
	}
}
