package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfatotp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func checkNativeMFAEnrollment(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("required native enrollment then fresh primary", func(t *testing.T) {
		tokens, input, _ := nativeIssuanceFixture(t, db, ctx)
		accessExec(t, db, ctx, `UPDATE auth.roles SET mfa_required=true WHERE id IN(SELECT role_id FROM auth.user_roles WHERE user_id=$1)`, input.Proof.UserID)
		cipher, err := secretbox.NewScoped(base64.StdEncoding.EncodeToString(make([]byte, 32)), "mfa:v1")
		if err != nil {
			t.Fatal(err)
		}
		mfa, err := mfaservice.NewLogin(mfapostgres.New(db), cipher, mfatotp.Authenticator{}, mfaTestLimit{}, tokengenerate.New(), mfaservice.LoginConfig{ChallengeTTL: 5 * time.Minute, SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour, UserLimitPerMinute: 5, IPLimitPerMinute: 10, GlobalLimitPerMinute: 500})
		if err != nil {
			t.Fatal(err)
		}
		login, err := tokenservice.NewNativeLogin(tokens, mfa)
		if err != nil {
			t.Fatal(err)
		}
		result, err := login.Begin(ctx, input)
		if err != nil || result.Challenge == nil || !result.Challenge.EnrollmentRequired || result.Tokens != nil {
			t.Fatal("required enrollment bypassed", err)
		}
		bound := mfaservice.LoginEnrollmentInput{Challenge: result.Challenge.Token, Binding: result.Challenge.Binding, IP: input.IP}
		if _, err := mfa.StartRequiredEnrollment(ctx, bound); !errors.Is(err, mfadomain.ErrInvalidCode) {
			t.Fatal("browser enrollment accepted native challenge", err)
		}
		enrollment, err := mfa.StartNativeRequiredEnrollment(ctx, bound)
		if err != nil {
			t.Fatal(err)
		}
		confirmation := mfaservice.ConfirmLoginEnrollmentInput{LoginEnrollmentInput: bound, Token: enrollment.Token, Code: mfaCode(t, db, ctx, enrollment.Secret, 0)}
		if _, err := mfa.ConfirmRequiredEnrollment(ctx, confirmation); !errors.Is(err, mfadomain.ErrInvalidCode) {
			t.Fatal("browser confirmation accepted native enrollment", err)
		}
		codes, err := mfa.ConfirmNativeRequiredEnrollment(ctx, confirmation)
		if err != nil || len(codes.Codes) != 10 {
			t.Fatal("native enrollment failed", err)
		}
		assertNativeRows(t, db, ctx, string(input.Proof.UserID), 0)
		if _, err := mfa.PrepareNativeCompletion(ctx, mfaservice.CompleteLoginInput{Token: bound.Challenge, Binding: bound.Binding, Recovery: true, Code: codes.Codes[0], IP: input.IP}); !errors.Is(err, mfadomain.ErrInvalidCode) {
			t.Fatal("pre-enrollment challenge survived version bump", err)
		}
		var email string
		if err := db.QueryRow(ctx, `SELECT email FROM auth.user_emails WHERE user_id=$1`, input.Proof.UserID).Scan(&email); err != nil {
			t.Fatal(err)
		}
		passwords := passwordservice.New(New(db), nil, hasher.NewBounded(hasher.NewArgon2idHash(2, 16, 1024, 1, 32), 2), loginTestLimit{})
		input.Proof, err = passwords.Authenticate(ctx, passwordservice.LoginInput{Email: email, Password: "Password12345", IP: input.IP})
		if err != nil {
			t.Fatal(err)
		}
		result, err = login.Begin(ctx, input)
		if err != nil || result.Challenge == nil || result.Challenge.EnrollmentRequired {
			t.Fatal("fresh login after enrollment failed", err)
		}
		if _, err := login.Complete(ctx, mfaservice.CompleteLoginInput{Token: result.Challenge.Token, Binding: result.Challenge.Binding, Recovery: true, Code: codes.Codes[0], IP: input.IP}); err != nil {
			t.Fatal("new factor cannot complete native login", err)
		}
	})
}
