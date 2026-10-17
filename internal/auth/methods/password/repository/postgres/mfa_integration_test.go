package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"

	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfatotp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

type mfaTestLimit struct{}

func (mfaTestLimit) AllowAll(context.Context, []mfaservice.Budget) (bool, error) {
	return true, nil
}

func (mfaTestLimit) Allow(context.Context, string, int, time.Duration) (bool, error) {
	return true, nil
}

func mfaService(t *testing.T, db *pgxpool.Pool) *mfaservice.Service {
	t.Helper()
	cipher, err := secretbox.NewScoped(base64.StdEncoding.EncodeToString(make([]byte, 32)), "mfa:v1")
	if err != nil {
		t.Fatal(err)
	}
	return mfaservice.New(mfapostgres.New(db), cipher, mfatotp.Authenticator{}, mfaTestLimit{}, "Auth")
}

func mfaProof(t *testing.T, db *pgxpool.Pool, ctx context.Context, f statusFixture) mfaservice.Proof {
	t.Helper()
	accessExec(t, db, ctx, `UPDATE auth.sessions SET password_verified_at=clock_timestamp() WHERE user_id=$1`, f.user)
	return mfaservice.Proof{UserID: f.user, TokenHash: f.params.TokenHash, AuthVersion: 1}
}

func mfaCode(t *testing.T, db *pgxpool.Pool, ctx context.Context, secret string, offset time.Duration) string {
	t.Helper()
	var now time.Time
	if err := db.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(secret, now.Add(offset))
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func checkMFAFoundation(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	svc := mfaService(t, db)
	t.Run("enroll-consume-reset-delete", func(t *testing.T) {
		f := newStatusFixture(t, db, ctx, "mfa-flow")
		proof := mfaProof(t, db, ctx, f)
		first, err := svc.StartEnrollment(ctx, proof)
		if err != nil {
			t.Fatal(err)
		}
		enrollment, err := svc.StartEnrollment(ctx, proof)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.ConfirmEnrollment(ctx, mfaservice.ConfirmInput{Proof: proof, Token: first.Token, Code: mfaCode(t, db, ctx, first.Secret, 0)}); !errors.Is(err, mfadomain.ErrInvalidCode) {
			t.Fatal("replaced enrollment accepted", err)
		}
		codes, err := svc.ConfirmEnrollment(ctx, mfaservice.ConfirmInput{Proof: proof, Token: enrollment.Token, Code: mfaCode(t, db, ctx, enrollment.Secret, 0)})
		if err != nil || len(codes.Codes) != 10 {
			t.Fatal("enrollment failed", err)
		}
		if _, err := svc.ConfirmEnrollment(ctx, mfaservice.ConfirmInput{Proof: proof, Token: enrollment.Token, Code: "123456"}); !errors.Is(err, mfadomain.ErrProofRequired) {
			t.Fatal("enrollment replay", err)
		}
		var encrypted []byte
		if err := db.QueryRow(ctx, `SELECT secret FROM auth.mfa_totp WHERE user_id=$1`, f.user).Scan(&encrypted); err != nil || strings.Contains(string(encrypted), enrollment.Secret) {
			t.Fatal("plaintext/absent secret", err)
		}
		if _, err := f.sessions.FindSession(ctx, proof.TokenHash); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
			t.Fatal("old session survived", err)
		}
		params := f.params
		params.AuthVersion = 2
		params.TokenHash = tokengenerate.New().Hash("mfa-primary-bypass")
		if _, err := f.sessions.CreateSession(ctx, params); !errors.Is(err, sessiondomain.ErrMFARequired) {
			t.Fatal("ordinary session bypassed MFA", err)
		}
		input := mfaservice.VerifyInput{UserID: f.user, AuthVersion: 2, Code: mfaCode(t, db, ctx, enrollment.Secret, 30*time.Second)}
		checkMFAOneWinner(t, ctx, svc, input)
		if _, err := svc.Verify(ctx, input); !errors.Is(err, mfadomain.ErrInvalidCode) {
			t.Fatal("TOTP replay", err)
		}
		checkMFARecoveryRace(t, db, ctx, svc, f, codes.Codes[0])
		input.Recovery = true
		input.Code = codes.Codes[1]
		input.AuthVersion = 1
		if _, err := svc.Verify(ctx, input); !errors.Is(err, mfadomain.ErrInvalidCode) {
			t.Fatal("stale authority", err)
		}
		input.UserID = f.actor
		if _, err := svc.Verify(ctx, input); !errors.Is(err, mfadomain.ErrInvalidCode) {
			t.Fatal("foreign recovery", err)
		}
		input.UserID = f.user
		input.AuthVersion = 2
		if _, err := svc.Verify(ctx, input); err != nil {
			t.Fatal("foreign/stale request burned code", err)
		}
		accessExec(t, db, ctx, `UPDATE auth.user_emails SET verified_at=clock_timestamp() WHERE user_id=$1`, f.user)
		reset := passworddomain.ResetChallenge{Digest: tokengenerate.New().Hash("mfa-reset"), Payload: make([]byte, 32), ExpiresAt: time.Now().Add(time.Hour)}
		if err := f.passwords.IssueReset(ctx, f.email, reset); err != nil {
			t.Fatal(err)
		}
		if err := f.passwords.ConsumeReset(ctx, reset.Digest, "replacement"); err != nil {
			t.Fatal(err)
		}
		params.AuthVersion = 3
		if _, err := f.sessions.CreateSession(ctx, params); !errors.Is(err, sessiondomain.ErrMFARequired) {
			t.Fatal("reset bypassed MFA", err)
		}
		if _, err := deleteFixture(ctx, f, 3); err != nil {
			t.Fatal(err)
		}
		var removed bool
		if err := db.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1)
			AND NOT EXISTS(SELECT 1 FROM auth.mfa_recovery_codes WHERE user_id=$1)`, f.user).Scan(&removed); err != nil || !removed {
			t.Fatal("deletion retained secrets", err)
		}
	})
	t.Run("enrollment-guarantees", func(t *testing.T) { checkMFAEnrollmentGuards(t, db, ctx, svc) })
	t.Run("consumption-rollback", func(t *testing.T) { checkMFAConsumptionRollback(t, db, ctx, svc) })
}
