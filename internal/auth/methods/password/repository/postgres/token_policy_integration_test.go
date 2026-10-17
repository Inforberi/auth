package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	tokendomain "github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	tokenpostgres "github.com/Inforberi/financial-intelligence/internal/auth/token/repository/postgres"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func checkSavedTokenSwitches(t *testing.T, db *pgxpool.Pool, ctx context.Context, actor accessservice.Principal) {
	t.Helper()
	available := settingsdomain.PublicMethods{Password: true, EmailOTP: true, Google: true, Telegram: true}
	repo := settingspostgres.NewWithRuntime(db, available, settingsdomain.TokenIssuance{SessionExchange: true, Native: true})
	svc := settingsservice.New(repo)
	before, err := svc.Read(ctx, actor)
	if err != nil {
		t.Fatal(err)
	}
	input := settingsservice.UpdateInput{Actor: actor, ExpectedVersion: before.Version, Policy: before.Policy}
	input.Policy.TokenIssuance.Native = true
	current, err := svc.Update(ctx, input)
	if err != nil || current.Version != before.Version+1 || !current.Policy.TokenIssuance.Native || current.Policy.TokenIssuance.SessionExchange {
		t.Fatal("independent native switch", current, err)
	}
	if got, err := repo.Initialize(ctx, before.Policy); err != nil || got != current {
		t.Fatal("restart reset saved token switches", got, err)
	}
	input.ExpectedVersion = current.Version
	if got, err := svc.Update(ctx, input); err != nil || got != current {
		t.Fatal("no-op changed settings", got, err)
	}
	var audited bool
	if err := db.QueryRow(ctx, `SELECT previous_policy->'TokenIssuance'->>'Native'='false' AND next_policy->'TokenIssuance'->>'Native'='true'
		FROM auth.auth_settings_audit WHERE version=$1`, current.Version).Scan(&audited); err != nil || !audited {
		t.Fatal("missing switch audit", err)
	}
	limited := settingsservice.New(settingspostgres.NewWithRuntime(db, available, settingsdomain.TokenIssuance{}))
	if _, err := limited.Update(ctx, input); !errors.Is(err, settingsdomain.ErrMethodNotReady) {
		t.Fatal("deployment ceiling bypassed", err)
	}
	input.Policy.TokenIssuance = settingsdomain.TokenIssuance{SessionExchange: true}
	current, err = svc.Update(ctx, input)
	if err != nil || current.Version != input.ExpectedVersion+1 || current.Policy.TokenIssuance.Native || !current.Policy.TokenIssuance.SessionExchange {
		t.Fatal("independent exchange switch", current, err)
	}
	input.ExpectedVersion = current.Version
	input.Policy.TokenIssuance = settingsdomain.TokenIssuance{}
	if _, err := limited.Update(ctx, input); err != nil {
		t.Fatal("could not disable after deployment removal", err)
	}
}

func checkTokenIssuancePolicy(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	set := func(exchange, native bool) {
		t.Helper()
		accessExec(t, db, ctx, `UPDATE auth.auth_settings SET token_session_exchange_enabled=$1,token_native_enabled=$2`, exchange, native)
	}
	defer set(true, true)
	t.Run("disabled exchange preserves introspection", func(t *testing.T) {
		defer set(true, true)
		signer, keys := jwtSigningFixture(t)
		svc := nativeTokenService(t, db, signer)
		input := jwtActor(t, db, ctx)
		issued, err := svc.Exchange(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		verifier, err := authjwt.NewVerifier(authjwt.Expectations{Issuer: "https://auth.example", Audience: "orders", Mode: authjwt.Strict}, keys, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		claims, err := verifier.VerifySignature(ctx, issued.Raw, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		set(false, false)
		if got, err := svc.Exchange(ctx, input); got != nil || !errors.Is(err, tokendomain.ErrForbidden) {
			t.Fatal("exchange switch ignored", err)
		}
		if _, err := tokenpostgres.New(db).Introspect(ctx, claims, input.Scope); err != nil {
			t.Fatal("switch revoked existing token", err)
		}
	})
	t.Run("native disabled before session and MFA consumption", func(t *testing.T) {
		defer set(true, true)
		svc, input, _ := nativeIssuanceFixture(t, db, ctx)
		f := newNativeMFAFixture(t, db, ctx, "issuance-disabled")
		set(true, false)
		if got, err := svc.IssueNative(ctx, input); got != nil || !errors.Is(err, settingsdomain.ErrMethodDisabled) {
			t.Fatal("native switch ignored", err)
		}
		assertNativeRows(t, db, ctx, string(input.Proof.UserID), 0)
		if got, err := f.coordinator.Complete(ctx, f.input); got != nil || !errors.Is(err, settingsdomain.ErrMethodDisabled) {
			t.Fatal("native MFA switch ignored", err)
		}
		assertNativeMFARows(t, db, ctx, f, 0)
		set(false, true)
		if got, err := f.coordinator.Complete(ctx, f.input); err != nil || got == nil {
			t.Fatal("denial consumed recovery proof/challenge", err)
		}
		if got, err := svc.IssueNative(ctx, input); err != nil || got == nil {
			t.Fatal("native depends on exchange switch", err)
		}
	})
	t.Run("disabled refresh rolls back but replay commits revoke", func(t *testing.T) {
		defer set(true, true)
		svc, binding, input, _ := refreshUseCaseFixture(t, db, ctx)
		set(true, false)
		if got, err := svc.Refresh(ctx, input); got != nil || !errors.Is(err, tokendomain.ErrForbidden) {
			t.Fatal("disabled refresh issued", err)
		}
		assertRefreshUnconsumed(t, db, ctx, binding.SessionID)
		set(true, true)
		if got, err := svc.Refresh(ctx, input); err != nil || got == nil {
			t.Fatal("disabled refresh lost credential", err)
		}
		set(false, false)
		if got, err := svc.Refresh(ctx, input); got != nil || !errors.Is(err, tokendomain.ErrInvalidRefresh) {
			t.Fatal("disabled replay", err)
		}
		assertNativeRevoked(t, db, ctx, binding.SessionID, true)
	})
	t.Run("logout remains available", func(t *testing.T) {
		defer set(true, true)
		svc, binding, input, _ := refreshUseCaseFixture(t, db, ctx)
		set(false, false)
		if err := svc.Logout(ctx, input); err != nil {
			t.Fatal(err)
		}
		assertNativeRevoked(t, db, ctx, binding.SessionID, true)
	})
	t.Run("exchange waits for current policy commit", func(t *testing.T) {
		defer set(true, true)
		signer, _ := jwtSigningFixture(t)
		svc := nativeTokenService(t, db, signer)
		input := jwtActor(t, db, ctx)
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }() //nolint:gosec // Commit closes the transaction.
		if _, err := tx.Exec(ctx, `UPDATE auth.auth_settings SET token_session_exchange_enabled=false`); err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() { _, err := svc.Exchange(ctx, input); result <- err }()
		waitJWTSQLLock(t, db, ctx)
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-result; !errors.Is(err, tokendomain.ErrForbidden) {
			t.Fatal("stale issuance policy", err)
		}
	})
	for _, operation := range []string{"native", "native MFA", "refresh"} {
		t.Run(operation+" waits for current policy commit", func(t *testing.T) {
			defer set(true, true)
			var issue func() error
			want := settingsdomain.ErrMethodDisabled
			switch operation {
			case "native":
				svc, input, _ := nativeIssuanceFixture(t, db, ctx)
				issue = func() error { _, err := svc.IssueNative(ctx, input); return err }
			case "native MFA":
				f := newNativeMFAFixture(t, db, ctx, "policy-wait")
				issue = func() error { _, err := f.coordinator.Complete(ctx, f.input); return err }
			case "refresh":
				svc, _, input, _ := refreshUseCaseFixture(t, db, ctx)
				issue = func() error { _, err := svc.Refresh(ctx, input); return err }
				want = tokendomain.ErrForbidden
			}
			tx, err := db.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }() //nolint:gosec // Commit closes the transaction.
			if _, err := tx.Exec(ctx, `UPDATE auth.auth_settings SET token_native_enabled=false`); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() { result <- issue() }()
			waitJWTSQLLock(t, db, ctx)
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-result; !errors.Is(err, want) {
				t.Fatal("stale native issuance policy", err)
			}
		})
	}
}
