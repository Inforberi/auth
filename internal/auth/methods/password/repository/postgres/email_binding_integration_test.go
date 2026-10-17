package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	otppostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/repository/postgres"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfatotp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

type bindingSQLFixture struct {
	statusFixture
	repo      *accountpostgres.Repository
	svc       *accountservice.EmailBindingService
	cipher    *secretbox.Cipher
	principal accessservice.Principal
	proof     mfaservice.Proof
	role      string
}

func newBindingFixture(t *testing.T, db *pgxpool.Pool, ctx context.Context, name string) bindingSQLFixture {
	t.Helper()
	f, _, proof, _ := emailProofFixture(t, db, ctx, "binding-"+name)
	accessExec(t, db, ctx, `DELETE FROM auth.user_emails WHERE user_id=$1`, f.user)
	actor := accessPrincipal(t, db, ctx)
	var role string
	if err := db.QueryRow(ctx, `INSERT INTO auth.roles(key,name) VALUES ($1,'Binding operator') RETURNING id`, "binding_"+strings.ReplaceAll(string(actor.UserID), "-", "")).Scan(&role); err != nil {
		t.Fatal(err)
	}
	accessExec(t, db, ctx, `INSERT INTO auth.role_permissions(role_id,permission_key) VALUES ($1,$2)`, role, accesssettings.EmailBindingManage)
	accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) VALUES ($1,$2)`, actor.UserID, role)
	t.Cleanup(func() {
		accessExec(t, db, ctx, `DELETE FROM auth.email_bindings WHERE user_id=$1`, f.user)
		accessExec(t, db, ctx, `DELETE FROM auth.user_roles WHERE role_id=$1`, role)
		accessExec(t, db, ctx, `DELETE FROM auth.role_permissions WHERE role_id=$1`, role)
		accessExec(t, db, ctx, `DELETE FROM auth.roles WHERE id=$1`, role)
	})
	cipher, err := secretbox.New("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	repo := accountpostgres.NewWithDelivery(db, accountpostgres.DeliveryConfig{EmailBinding: true})
	svc := accountservice.NewEmailBinding(repo, verificationLimits{}, cipher, accountservice.EmailBindingConfig{Enabled: true, TTL: 5 * time.Minute, RequestsPerMinute: 100, ConfirmationsPerMinute: 1000})
	return bindingSQLFixture{statusFixture: f, repo: repo, svc: svc, cipher: cipher, principal: actor, proof: proof, role: role}
}

func (f bindingSQLFixture) issue(t *testing.T, db *pgxpool.Pool, ctx context.Context, email string) string {
	t.Helper()
	deadline, err := f.svc.Request(ctx, accountservice.EmailBindingInput{Actor: f.principal, UserID: f.user, Email: email, IP: "192.0.2.1"})
	if err != nil || !deadline.After(time.Now()) || deadline.After(time.Now().Add(5*time.Minute)) {
		t.Fatal(deadline, err)
	}
	var payload []byte
	if err := db.QueryRow(ctx, `SELECT payload FROM auth.email_bindings WHERE user_id=$1`, f.user).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	return bindingMailCode(t, f.cipher, payload, email)
}

func bindingMailCode(t *testing.T, cipher *secretbox.Cipher, payload []byte, email string) string {
	t.Helper()
	plain, err := cipher.Open(payload)
	if err != nil {
		t.Fatal(err)
	}
	var mail struct{ To, Body string }
	if err := json.Unmarshal(plain, &mail); err != nil || mail.To != email {
		t.Fatal("wrong recipient", mail, err)
	}
	index := strings.Index(mail.Body, "<strong>") + len("<strong>")
	if index < len("<strong>") || len(mail.Body) < index+8 {
		t.Fatal("missing code")
	}
	return mail.Body[index : index+8]
}

func checkEmailBinding(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("delivery-one-winner-no-merge", func(t *testing.T) {
		f := newBindingFixture(t, db, ctx, "success")
		code := f.issue(t, db, ctx, f.email)
		var count int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.user_emails WHERE email=$1`, f.email).Scan(&count); err != nil || count != 0 {
			t.Fatal("address reserved before ownership proof", count, err)
		}
		job, err := f.repo.ClaimDelivery(ctx)
		if err != nil || job == nil || !job.EmailBinding {
			t.Fatal(job, err)
		}
		if bindingMailCode(t, f.cipher, job.Payload, f.email) != code {
			t.Fatal("delivery payload changed")
		}
		if err := f.repo.FinishDelivery(ctx, *job, true); err != nil {
			t.Fatal(err)
		}
		if next, err := f.repo.ClaimDelivery(ctx); err != nil || next != nil {
			t.Fatal("sent mail reclaimed", next, err)
		}
		var wg sync.WaitGroup
		var wins atomic.Int64
		for range 16 {
			wg.Go(func() {
				if err := f.svc.Confirm(ctx, f.proof, code, "192.0.2.1"); err == nil {
					wins.Add(1)
				} else if !errors.Is(err, accountdomain.ErrInvalidEmailBinding) && !errors.Is(err, accountdomain.ErrEmailBindingConflict) {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatal("completion winners", wins.Load())
		}
		if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.user_emails WHERE user_id=$1 AND email=$2 AND verified_at IS NOT NULL`, f.user, f.email).Scan(&count); err != nil || count != 1 {
			t.Fatal(err, count)
		}
		var version int64
		if err := db.QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1`, f.user).Scan(&version); err != nil || version != 2 {
			t.Fatal(version, err)
		}
		if _, err := f.sessions.FindSession(ctx, f.proof.TokenHash); err == nil {
			t.Fatal("old owner session survived binding")
		}
		if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.password_credentials WHERE user_id=$1`, f.user).Scan(&count); err != nil || count != 0 {
			t.Fatal("binding created credentials", count, err)
		}
		if err := f.svc.Confirm(ctx, f.proof, code, "192.0.2.1"); err == nil {
			t.Fatal("binding replay")
		}
		params := f.params
		params.AuthVersion = 2
		params.TokenHash = tokengenerate.New().Hash("bound-session-" + string(f.user))
		if _, err := f.sessions.CreateSession(ctx, params); err != nil {
			t.Fatal(err)
		}
		proof := mfaservice.Proof{UserID: f.user, AuthVersion: 2, TokenHash: params.TokenHash}
		cipher, err := secretbox.NewScoped("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "email-login:v1")
		if err != nil {
			t.Fatal(err)
		}
		otpRepo := otppostgres.New(db)
		otp := otpservice.New(otpRepo, cipher, verificationLimits{}, nil, tokengenerate.New(), otpservice.Config{
			ReauthenticationEnabled: true, TTL: 5 * time.Minute, ResendInterval: time.Minute, RequestGlobalLimit: 100, ConfirmGlobalLimit: 1000,
		})
		flow, err := otp.RequestReauthentication(ctx, proof, f.email, "192.0.2.1")
		if err != nil {
			t.Fatal("bound contact cannot authorize MFA", err)
		}
		var otpPayload []byte
		if err := db.QueryRow(ctx, `SELECT o.payload FROM auth.email_login_outbox o JOIN auth.email_login_challenges c ON c.digest=o.digest WHERE c.user_id=$1`, f.user).Scan(&otpPayload); err != nil {
			t.Fatal(err)
		}
		confirmed, err := otp.ConfirmReauthentication(ctx, otpservice.ReauthenticationInput{Proof: proof, Binding: flow.Binding, Code: bindingMailCode(t, cipher, otpPayload, f.email), IP: "192.0.2.1"})
		if err != nil {
			t.Fatal(err)
		}
		proof.TokenHash = tokengenerate.New().Hash(confirmed.Token)
		mfaCipher, err := secretbox.NewScoped("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "mfa:v1")
		if err != nil {
			t.Fatal(err)
		}
		mfa := mfaservice.New(mfapostgres.NewWithEmailProof(db, true), mfaCipher, mfatotp.Authenticator{}, mfaTestLimit{}, "Auth")
		enrollment, err := mfa.StartEnrollment(ctx, proof)
		if err != nil {
			t.Fatal(err)
		}
		codes, err := mfa.ConfirmEnrollment(ctx, mfaservice.ConfirmInput{Proof: proof, Token: enrollment.Token, Code: mfaCode(t, db, ctx, enrollment.Secret, 0)})
		if err != nil || len(codes.Codes) != 10 {
			t.Fatal("binding to MFA chain", err, codes)
		}
	})
	t.Run("five-attempts-and-foreign-owner", func(t *testing.T) {
		f := newBindingFixture(t, db, ctx, "attempts")
		code := f.issue(t, db, ctx, f.email)
		foreign := f.proof
		foreign.UserID = f.actor
		if err := f.svc.Confirm(ctx, foreign, code, ""); err == nil {
			t.Fatal("foreign user consumed binding")
		}
		wrong := "00000000"
		if wrong == code {
			wrong = "11111111"
		}
		for range 5 {
			if err := f.svc.Confirm(ctx, f.proof, wrong, ""); !errors.Is(err, accountdomain.ErrInvalidEmailBinding) {
				t.Fatal(err)
			}
		}
		var attempts int
		if err := db.QueryRow(ctx, `SELECT attempts FROM auth.email_bindings WHERE user_id=$1`, f.user).Scan(&attempts); err != nil || attempts != 5 {
			t.Fatal(attempts, err)
		}
		if err := f.svc.Confirm(ctx, f.proof, code, ""); !errors.Is(err, accountdomain.ErrInvalidEmailBinding) {
			t.Fatal("exhausted code", err)
		}
	})
	for _, guard := range []string{"permission", "actor-password", "actor-mfa", "actor-session", "actor-blocked", "owner-mfa", "owner-revoked", "owner-blocked", "version", "existing-email", "expired", "audit"} {
		t.Run(guard, func(t *testing.T) {
			f := newBindingFixture(t, db, ctx, guard)
			code := f.issue(t, db, ctx, f.email)
			switch guard {
			case "permission":
				accessExec(t, db, ctx, `DELETE FROM auth.role_permissions WHERE role_id=$1`, f.role)
			case "actor-password":
				accessExec(t, db, ctx, `UPDATE auth.sessions SET password_verified_at=NULL WHERE token_hash=$1`, f.principal.TokenHash)
			case "actor-mfa":
				accessExec(t, db, ctx, `UPDATE auth.sessions SET mfa_verified_at=NULL WHERE token_hash=$1`, f.principal.TokenHash)
			case "actor-session":
				accessExec(t, db, ctx, `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE token_hash=$1`, f.principal.TokenHash)
			case "actor-blocked":
				accessExec(t, db, ctx, `UPDATE auth.users SET status='blocked' WHERE id=$1`, f.principal.UserID)
			case "owner-mfa":
				accessExec(t, db, ctx, `INSERT INTO auth.mfa_totp(user_id,secret,last_step) VALUES ($1,$2,0)`, f.user, make([]byte, 48))
			case "owner-revoked":
				accessExec(t, db, ctx, `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE token_hash=$1`, f.proof.TokenHash)
			case "owner-blocked":
				accessExec(t, db, ctx, `UPDATE auth.users SET status='blocked' WHERE id=$1`, f.user)
			case "version":
				accessExec(t, db, ctx, `UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`, f.user)
			case "existing-email":
				accessExec(t, db, ctx, `INSERT INTO auth.user_emails(user_id,email) VALUES ($1,$2)`, f.user, "other-"+f.email)
			case "expired":
				accessExec(t, db, ctx, `UPDATE auth.email_bindings SET created_at=clock_timestamp()-interval '6 minutes',expires_at=clock_timestamp()-interval '2 minutes' WHERE user_id=$1`, f.user)
			case "audit":
				accessExec(t, db, ctx, `ALTER TABLE auth.email_verification_audit ADD CONSTRAINT binding_audit_failure CHECK (event<>'email_bound') NOT VALID`)
				t.Cleanup(func() {
					accessExec(t, db, ctx, `ALTER TABLE auth.email_verification_audit DROP CONSTRAINT binding_audit_failure`)
				})
			}
			if err := f.svc.Confirm(ctx, f.proof, code, ""); err == nil {
				t.Fatal("binding guard bypassed", guard)
			}
			var count int
			if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.user_emails WHERE email=$1`, f.email).Scan(&count); err != nil || count != 0 {
				t.Fatal("failed binding created contact", count, err)
			}
			if guard == "audit" {
				if _, err := f.sessions.FindSession(ctx, f.proof.TokenHash); err != nil {
					t.Fatal("audit failure revoked session", err)
				}
				if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.email_bindings WHERE user_id=$1`, f.user).Scan(&count); err != nil || count != 1 {
					t.Fatal("audit failure consumed intent", count, err)
				}
			}
		})
	}
	t.Run("unauthorized-approval", func(t *testing.T) {
		f := newBindingFixture(t, db, ctx, "unauthorized")
		if err := mfaManagement(t, db).Disable(ctx, mfaservice.Proof{UserID: f.principal.UserID, TokenHash: f.principal.TokenHash, AuthVersion: 1}); !errors.Is(err, mfadomain.ErrRequiredByPolicy) {
			t.Fatal("binding administrator disabled mandatory MFA", err)
		}
		accessExec(t, db, ctx, `DELETE FROM auth.role_permissions WHERE role_id=$1`, f.role)
		if _, err := f.svc.Request(ctx, accountservice.EmailBindingInput{Actor: f.principal, UserID: f.user, Email: f.email}); !errors.Is(err, accessdomain.ErrForbidden) {
			t.Fatal(err)
		}
	})
	t.Run("fresh-owner-factor-preserved", func(t *testing.T) {
		f := newBindingFixture(t, db, ctx, "fresh-factor")
		code := f.issue(t, db, ctx, f.email)
		accessExec(t, db, ctx, `INSERT INTO auth.mfa_totp(user_id,secret,last_step) VALUES ($1,$2,0)`, f.user, make([]byte, 48))
		accessExec(t, db, ctx, `UPDATE auth.sessions SET primary_method='oidc',primary_verified_at=clock_timestamp(),mfa_verified_at=clock_timestamp() WHERE token_hash=$1`, f.proof.TokenHash)
		if err := f.svc.Confirm(ctx, f.proof, code, ""); err != nil {
			t.Fatal(err)
		}
		var factors int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.mfa_totp WHERE user_id=$1`, f.user).Scan(&factors); err != nil || factors != 1 {
			t.Fatal("binding removed existing factor", factors, err)
		}
	})
	t.Run("same-address-two-accounts", func(t *testing.T) {
		first := newBindingFixture(t, db, ctx, "race-first")
		second := newBindingFixture(t, db, ctx, "race-second")
		firstCode := first.issue(t, db, ctx, first.email)
		secondCode := second.issue(t, db, ctx, first.email)
		results := make(chan error, 2)
		go func() { results <- first.svc.Confirm(ctx, first.proof, firstCode, "") }()
		go func() { results <- second.svc.Confirm(ctx, second.proof, secondCode, "") }()
		a, b := <-results, <-results
		winners := 0
		for _, err := range []error{a, b} {
			if err == nil {
				winners++
			} else if !errors.Is(err, accountdomain.ErrEmailBindingConflict) {
				t.Fatal(err)
			}
		}
		if winners != 1 {
			t.Fatal("address conflict silently merged", a, b)
		}
	})
}
