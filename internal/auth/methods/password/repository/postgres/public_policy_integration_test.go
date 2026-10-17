package postgres

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	passwordhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func TestPublicPolicySchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	repo := settingspostgres.NewWithRuntime(db, settingsdomain.PublicMethods{Password: true, EmailOTP: true, Google: true, Telegram: true})
	service := settingsservice.New(repo)
	baseline, err := repo.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	actor := accessPrincipal(t, db, ctx)
	prepareUsableAdministrator(t, db, ctx, actor.UserID)
	accessExec(t, db, ctx, `WITH r AS(INSERT INTO auth.roles(key,name) VALUES('policy_operator','Policy operator') RETURNING id),
		p AS(INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,'auth.settings.manage' FROM r)
		INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM r`, actor.UserID)
	update := func(policy settingsdomain.Policy) error {
		current, err := repo.Load(ctx)
		if err != nil {
			return err
		}
		_, err = service.Update(ctx, settingsservice.UpdateInput{Actor: actor, ExpectedVersion: current.Version, Policy: policy})
		return err
	}
	set := func(t *testing.T, policy settingsdomain.Policy) {
		t.Helper()
		if err := update(policy); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("verification-profiles", func(t *testing.T) {
		defer set(t, baseline.Policy)
		f := newRegistrationFixture(t, db, ctx)
		for _, mode := range []settingsdomain.EmailVerification{settingsdomain.VerificationDisabled, settingsdomain.VerificationOptional, settingsdomain.VerificationRequired} {
			p := baseline.Policy
			p.PasswordEmailVerification = mode
			set(t, p)
			email := "registration-policy-" + string(mode) + "@example.com"
			request := httptest.NewRequest("POST", "/api/v1/auth/register/email", strings.NewReader(`{"email":"`+email+`","password":"ExamplePass1"}`)).WithContext(ctx)
			request.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			passwordhttp.New(f.service, zap.NewNop()).Register(w, request)
			if w.Code != 201 {
				t.Fatal(mode, w.Code, w.Body.String())
			}
			var user accountdomain.UserID
			var verified *time.Time
			var messages int
			if err := db.QueryRow(ctx, `SELECT e.user_id,e.verified_at,(SELECT count(*) FROM auth.email_verifications v WHERE v.email_id=e.id) FROM auth.user_emails e WHERE email=$1`, email).Scan(&user, &verified, &messages); err != nil || verified != nil {
				t.Fatal("invented verification", err)
			}
			wantMessages := 1
			if mode == settingsdomain.VerificationDisabled {
				wantMessages = 0
			}
			if messages != wantMessages {
				t.Fatal("automatic verification delivery", mode, messages)
			}
			if mode == settingsdomain.VerificationRequired {
				if len(w.Result().Cookies()) != 0 || !strings.Contains(w.Body.String(), `"verificationRequired":true`) {
					t.Fatal("required registration issued cookie", w.Body.String())
				}
				if _, err := f.service.Login(ctx, passwordservice.LoginInput{Email: email, Password: "ExamplePass1"}); !errors.Is(err, accountdomain.ErrEmailUnverified) {
					t.Fatal("required login issued session", err)
				}
				accessExec(t, db, ctx, `UPDATE auth.user_emails SET verified_at=clock_timestamp() WHERE user_id=$1`, user)
				if _, err := f.service.Login(ctx, passwordservice.LoginInput{Email: email, Password: "ExamplePass1"}); err != nil {
					t.Fatal("verified user cannot login", err)
				}
			} else if len(w.Result().Cookies()) != 1 {
				t.Fatal("optional/disabled lost session", mode)
			}
		}
	})
	t.Run("disabled-methods-and-pending-mfa", func(t *testing.T) {
		defer set(t, baseline.Policy)
		f := newMFALoginFixture(t, db, ctx, "policy-disable")
		plain := newStatusFixture(t, db, ctx, "policy-disabled-session")
		existingSessionHash := plain.params.TokenHash
		plain.params.TokenHash = strings.Repeat("c", 64)
		admin := newMFALoginFixture(t, db, ctx, "policy-private-admin")
		admin.proof.Administrative = true
		accessExec(t, db, ctx, `UPDATE auth.user_emails SET verified_at=clock_timestamp() WHERE user_id=$1`, admin.user)
		accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM auth.roles WHERE key='policy_operator'`, admin.user)
		pending := f.start(t, ctx)
		p := baseline.Policy
		p.Methods = settingsdomain.PublicMethods{}
		set(t, p)
		if _, err := plain.sessions.FindSession(ctx, existingSessionHash); err != nil {
			t.Fatal("method disable implicitly revoked existing session", err)
		}
		if _, err := f.login.Complete(ctx, pending); !errors.Is(err, settingsdomain.ErrMethodDisabled) {
			t.Fatal("pending MFA bypassed policy", err)
		}
		if _, err := plain.sessions.CreateSession(ctx, plain.params); !errors.Is(err, settingsdomain.ErrMethodDisabled) {
			t.Fatal("direct session bypass", err)
		}
		if _, err := New(db).CreateUser(ctx, "disabled-registration@example.com", "hash"); !errors.Is(err, settingsdomain.ErrMethodDisabled) {
			t.Fatal("direct registration bypass", err)
		}
		if _, err := accountpostgres.New(db).ResolveIdentityAccount(ctx, accountdomain.IdentityKey{Issuer: "https://accounts.google.com", Subject: "disabled"}, true); !errors.Is(err, settingsdomain.ErrMethodDisabled) {
			t.Fatal("direct provider registration bypass", err)
		}
		if _, err := admin.login.Complete(ctx, admin.start(t, ctx)); err != nil {
			t.Fatal("public switches disabled administrator", err)
		}
		set(t, baseline.Policy)
		if _, err := f.login.Complete(ctx, pending); err != nil {
			t.Fatal("policy denial consumed factor", err)
		}
	})
	t.Run("registration-separate-from-login", func(t *testing.T) {
		defer set(t, baseline.Policy)
		f := newStatusFixture(t, db, ctx, "policy-registration")
		p := baseline.Policy
		p.Registration.Enabled = false
		set(t, p)
		if _, err := New(db).CreateUser(ctx, "closed-registration@example.com", "hash"); !errors.Is(err, settingsdomain.ErrRegistrationDisabled) {
			t.Fatal(err)
		}
		f.params.TokenHash = strings.Repeat("e", 64)
		if _, err := f.sessions.CreateSession(ctx, f.params); err != nil {
			t.Fatal("closed registration disabled existing login", err)
		}
	})
	t.Run("otp-consume-and-provider-link", func(t *testing.T) {
		defer set(t, baseline.Policy)
		f, otp, c := otpSQLFixture(t, db, ctx, "policy")
		if err := otp.Issue(ctx, f.email, c); err != nil {
			t.Fatal(err)
		}
		identity, management := identityManagementFixture(t, db, ctx, "policy")
		p := baseline.Policy
		p.Methods.EmailOTP = false
		p.Methods.Telegram = false
		set(t, p)
		if _, err := otp.Consume(ctx, c.Digest, c.Verifier); !errors.Is(err, settingsdomain.ErrMethodDisabled) {
			t.Fatal("OTP consumed after disable", err)
		}
		if err := management.Link(ctx, identity.user, identity.params.TokenHash, accountdomain.IdentityKey{Issuer: "https://oauth.telegram.org", Subject: "disabled-link"}); !errors.Is(err, settingsdomain.ErrMethodDisabled) {
			t.Fatal("disabled link", err)
		}
		set(t, baseline.Policy)
		if _, err := otp.Consume(ctx, c.Digest, c.Verifier); err != nil {
			t.Fatal("policy denial consumed OTP", err)
		}
	})
	t.Run("policy-update-waits-for-public-commit", func(t *testing.T) {
		defer set(t, baseline.Policy)
		f := newStatusFixture(t, db, ctx, "policy-lock")
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `SELECT id FROM auth.users WHERE id=$1 FOR SHARE`, f.user); err != nil {
			t.Fatal(err)
		}
		if err := settingspostgres.RequirePublicLogin(ctx, tx, f.user, "password", ""); err != nil {
			t.Fatal(err)
		}
		p := baseline.Policy
		p.Methods.Password = false
		done := make(chan error, 1)
		go func() { done <- update(p) }()
		poll := time.NewTicker(5 * time.Millisecond)
		defer poll.Stop()
		waitCtx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		waiting := false
		for !waiting {
			if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%auth.auth_settings%FOR UPDATE%')`).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if !waiting {
				select {
				case <-poll.C:
				case <-waitCtx.Done():
					t.Fatal("policy update did not wait")
				}
			}
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		f.params.TokenHash = strings.Repeat("f", 64)
		if _, err := f.sessions.CreateSession(ctx, f.params); !errors.Is(err, settingsdomain.ErrMethodDisabled) {
			t.Fatal("committed disable not seen", err)
		}
	})
	t.Run("primary-source-and-provider-registration", func(t *testing.T) {
		defer set(t, baseline.Policy)
		f := newStatusFixture(t, db, ctx, "policy-primary")
		key := accountdomain.IdentityKey{Issuer: "https://accounts.google.com", Subject: "policy-source"}
		accessExec(t, db, ctx, `INSERT INTO auth.linked_identities(issuer,subject,user_id) VALUES($1,$2,$3)`, key.Issuer, key.Subject, f.user)
		p := baseline.Policy
		p.Methods.Password = false
		p.Registration.Google = false
		set(t, p)
		resolved, err := f.accounts.ResolveIdentityAccount(ctx, key, true)
		if err != nil || resolved.ID != f.user {
			t.Fatal("provider registration flag disabled existing identity", err)
		}
		if _, err := f.accounts.ResolveIdentityAccount(ctx, accountdomain.IdentityKey{Issuer: key.Issuer, Subject: "new-disabled-registration"}, true); !errors.Is(err, settingsdomain.ErrRegistrationDisabled) {
			t.Fatal("provider registration bypass", err)
		}
		sessions := sessionservice.New(clock.UTCClock{}, f.sessions, tokengenerate.New(), sessionservice.Config{SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour})
		proof := mfaservice.PrimaryProof{UserID: f.user, AuthVersion: 1, Method: "oidc", Issuer: key.Issuer, Reference: key.Subject, VerifiedAt: time.Now().UTC()}
		created, err := sessions.BeginLogin(ctx, proof, "", "")
		if err != nil {
			t.Fatal("OIDC treated as disabled password", err)
		}
		stored, err := f.sessions.FindSession(ctx, tokengenerate.New().Hash(created.RawToken))
		if err != nil || stored.PrimaryMethod != "oidc" {
			t.Fatal("primary context lost", err)
		}
		p.Methods.Google = false
		set(t, p)
		if _, err := sessions.BeginLogin(ctx, proof, "", ""); !errors.Is(err, settingsdomain.ErrMethodDisabled) {
			t.Fatal("plain OIDC session bypass", err)
		}
	})
	t.Run("required-verification-on-pending-mfa", func(t *testing.T) {
		defer set(t, baseline.Policy)
		f := newMFALoginFixture(t, db, ctx, "policy-verify-mfa")
		pending := f.start(t, ctx)
		p := baseline.Policy
		p.PasswordEmailVerification = settingsdomain.VerificationRequired
		set(t, p)
		if _, err := f.login.Complete(ctx, pending); !errors.Is(err, accountdomain.ErrEmailUnverified) {
			t.Fatal("pending MFA bypassed verification policy", err)
		}
		accessExec(t, db, ctx, `UPDATE auth.user_emails SET verified_at=clock_timestamp() WHERE user_id=$1`, f.user)
		if _, err := f.login.Complete(ctx, pending); err != nil {
			t.Fatal("verification denial consumed factor", err)
		}
	})
	t.Run("missing-policy-fails-closed", func(t *testing.T) {
		f := newStatusFixture(t, db, ctx, "policy-missing")
		accessExec(t, db, ctx, `DELETE FROM auth.auth_settings`)
		f.params.TokenHash = strings.Repeat("d", 64)
		if _, err := f.sessions.CreateSession(ctx, f.params); !errors.Is(err, settingsdomain.ErrPolicyUnavailable) {
			t.Fatal("missing policy fallback", err)
		}
	})
}
