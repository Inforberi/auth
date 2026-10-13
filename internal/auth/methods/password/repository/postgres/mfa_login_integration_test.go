package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfatotp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

type mfaLoginFixture struct {
	statusFixture
	login  *mfaservice.Login
	proof  mfaservice.PrimaryProof
	secret string
	codes  []string
}

func newMFALoginFixture(t *testing.T, db *pgxpool.Pool, ctx context.Context, name string) mfaLoginFixture {
	t.Helper()
	f := newStatusFixture(t, db, ctx, "mfa-login-"+name)
	svc := mfaService(t, db)
	proof := mfaProof(t, db, ctx, f)
	enrollment, err := svc.StartEnrollment(ctx, proof)
	if err != nil {
		t.Fatal(err)
	}
	codes, err := svc.ConfirmEnrollment(ctx, mfaservice.ConfirmInput{Proof: proof, Token: enrollment.Token, Code: mfaCode(t, db, ctx, enrollment.Secret, 0)})
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := secretbox.NewScoped(base64.StdEncoding.EncodeToString(make([]byte, 32)), "mfa:v1")
	if err != nil {
		t.Fatal(err)
	}
	login, err := mfaservice.NewLogin(mfapostgres.New(db), cipher, mfatotp.Authenticator{}, mfaTestLimit{}, tokengenerate.New(), mfaservice.LoginConfig{
		ChallengeTTL: 5 * time.Minute, SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour,
		UserLimitPerMinute: 5, IPLimitPerMinute: 10, GlobalLimitPerMinute: 500,
	})
	if err != nil {
		t.Fatal(err)
	}
	return mfaLoginFixture{
		statusFixture: f, login: login, secret: enrollment.Secret, codes: codes.Codes,
		proof: mfaservice.PrimaryProof{UserID: f.user, AuthVersion: 2, Method: "password", Reference: "old-hash", VerifiedAt: time.Now().UTC()},
	}
}

func (f mfaLoginFixture) start(t *testing.T, ctx context.Context) mfaservice.CompleteLoginInput {
	t.Helper()
	challenge, err := f.login.Start(ctx, f.proof, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	return mfaservice.CompleteLoginInput{Token: challenge.Token, Binding: challenge.Binding, Code: f.codes[0], Recovery: true, UserAgent: "MFA test", IP: "192.0.2.1"}
}

func checkMFALogin(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	for _, recovery := range []bool{true, false} {
		name := "totp"
		if recovery {
			name = "recovery"
		}
		t.Run(name+"-race-and-context", func(t *testing.T) {
			f := newMFALoginFixture(t, db, ctx, name)
			input := f.start(t, ctx)
			input.Recovery = recovery
			if !recovery {
				input.Code = mfaCode(t, db, ctx, f.secret, 30*time.Second)
			}
			var wg sync.WaitGroup
			results := make(chan *mfaservice.LoginSession, 16)
			failures := make(chan error, 16)
			for range 16 {
				wg.Go(func() { result, err := f.login.Complete(ctx, input); results <- result; failures <- err })
			}
			wg.Wait()
			close(results)
			close(failures)
			var winner *mfaservice.LoginSession
			winners := 0
			for result := range results {
				if result != nil {
					winner = result
					winners++
				}
			}
			for err := range failures {
				if err != nil && !errors.Is(err, mfadomain.ErrInvalidCode) {
					t.Fatal(err)
				}
			}
			if winners != 1 {
				t.Fatal("challenge must have one winner", winners)
			}
			hash := tokengenerate.New().Hash(winner.Token)
			session, err := f.sessions.FindSession(ctx, hash)
			if err != nil || session.PrimaryMethod != "password" || session.PrimaryVerifiedAt == nil || session.MFAVerifiedAt == nil ||
				session.PrimaryVerifiedAt.After(*session.MFAVerifiedAt) || !session.MFAVerifiedAt.Equal(winner.MFAVerified) {
				t.Fatal("session authentication context", err)
			}
			var count, pending int
			if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM auth.sessions WHERE user_id=$1 AND revoked_at IS NULL),
				(SELECT count(*) FROM auth.mfa_login_challenges WHERE user_id=$1)`, f.user).Scan(&count, &pending); err != nil || count != 1 || pending != 0 {
				t.Fatal("partial/duplicate completion", count, pending, err)
			}
			cfg := sessionservice.Config{SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour}
			validation, err := sessionservice.New(clock.UTCClock{}, f.sessions, tokengenerate.New(), cfg).ValidateSessionWithoutRefresh(ctx, winner.Token)
			if err != nil || validation.MFAVerifiedAt == nil || validation.PrimaryMethod != "password" {
				t.Fatal("context lost in validation", err)
			}
			newHash := tokengenerate.New().Hash("rotated-mfa-" + name)
			if _, err := f.sessions.RotateSession(ctx, f.user, hash, newHash); err != nil {
				t.Fatal(err)
			}
			rotated, err := f.sessions.FindSession(ctx, newHash)
			if err != nil || rotated.MFAVerifiedAt == nil || !rotated.MFAVerifiedAt.Equal(*session.MFAVerifiedAt) {
				t.Fatal("rotation lost MFA", err)
			}
			rotated.ExpiresAt = rotated.ExpiresAt.Add(10 * time.Minute)
			if _, err := f.sessions.RefreshSession(ctx, newHash, rotated, session.ExpiresAt); err != nil {
				t.Fatal(err)
			}
			refreshed, err := f.sessions.FindSession(ctx, newHash)
			if err != nil || refreshed.MFAVerifiedAt == nil || !refreshed.MFAVerifiedAt.Equal(*session.MFAVerifiedAt) {
				t.Fatal("refresh renewed MFA freshness", err)
			}
		})
	}
	t.Run("binding-attempts-replacement", func(t *testing.T) {
		f := newMFALoginFixture(t, db, ctx, "attempts")
		input := f.start(t, ctx)
		wrong := input
		wrong.Binding = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		if result, err := f.login.Complete(ctx, wrong); result != nil || !errors.Is(err, mfadomain.ErrInvalidCode) {
			t.Fatal("foreign binding", err)
		}
		var attempts int
		if err := db.QueryRow(ctx, `SELECT attempts FROM auth.mfa_login_challenges WHERE user_id=$1`, f.user).Scan(&attempts); err != nil || attempts != 0 {
			t.Fatal("foreign browser burned attempts", attempts, err)
		}
		wrong = input
		wrong.Code = strings.Repeat("0", 32)
		for range 6 {
			if _, err := f.login.Complete(ctx, wrong); !errors.Is(err, mfadomain.ErrInvalidCode) {
				t.Fatal(err)
			}
		}
		if err := db.QueryRow(ctx, `SELECT attempts FROM auth.mfa_login_challenges WHERE user_id=$1`, f.user).Scan(&attempts); err != nil || attempts != 5 {
			t.Fatal("attempts not bounded/committed", attempts, err)
		}
		if _, err := f.login.Complete(ctx, input); !errors.Is(err, mfadomain.ErrInvalidCode) {
			t.Fatal("exhausted challenge", err)
		}
		replacement := f.start(t, ctx)
		if _, err := f.login.Complete(ctx, input); !errors.Is(err, mfadomain.ErrInvalidCode) {
			t.Fatal("replaced challenge", err)
		}
		if _, err := f.login.Complete(ctx, replacement); err != nil {
			t.Fatal("rejected requests burned valid recovery", err)
		}
	})
	t.Run("state-guards", func(t *testing.T) { checkMFALoginGuards(t, db, ctx) })
	t.Run("atomic-rollback", func(t *testing.T) { checkMFALoginRollback(t, db, ctx) })
}
