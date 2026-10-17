package postgres

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	otpdomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
	otppostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/repository/postgres"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfatotp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type nativeEmailFixture struct {
	user    accountdomain.UserID
	email   string
	login   *tokenservice.NativeEmailLogin
	primary *tokenservice.NativeLogin
	mfa     *mfaservice.Login
	tokens  *tokenservice.Service
	keys    *authjwt.PublicKeys
	otp     *otpservice.Service
	cipher  *secretbox.Cipher
}

func newNativeEmailFixture(t *testing.T, db *pgxpool.Pool, ctx context.Context) nativeEmailFixture {
	t.Helper()
	tokens, input, keys := nativeIssuanceFixture(t, db, ctx)
	f := nativeEmailFixture{user: input.Proof.UserID, tokens: tokens, keys: keys}
	if err := db.QueryRow(ctx, `UPDATE auth.user_emails SET verified_at=clock_timestamp() WHERE user_id=$1 RETURNING email`, f.user).Scan(&f.email); err != nil {
		t.Fatal(err)
	}
	mfaCipher, err := secretbox.NewScoped(base64.StdEncoding.EncodeToString(make([]byte, 32)), "mfa:v1")
	if err != nil {
		t.Fatal(err)
	}
	f.mfa, err = mfaservice.NewLogin(mfapostgres.New(db), mfaCipher, mfatotp.Authenticator{}, mfaTestLimit{}, tokengenerate.New(), mfaservice.LoginConfig{ChallengeTTL: 5 * time.Minute, SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour, UserLimitPerMinute: 5, IPLimitPerMinute: 10, GlobalLimitPerMinute: 500})
	if err != nil {
		t.Fatal(err)
	}
	f.primary, err = tokenservice.NewNativeLogin(tokens, f.mfa)
	if err != nil {
		t.Fatal(err)
	}
	f.cipher, err = secretbox.NewScoped(base64.StdEncoding.EncodeToString(make([]byte, 32)), "email-login:v1")
	if err != nil {
		t.Fatal(err)
	}
	f.otp = otpservice.New(otppostgres.New(db), f.cipher, mfaTestLimit{}, nil, tokengenerate.New(), otpservice.Config{Enabled: true, TTL: 5 * time.Minute, ResendInterval: time.Minute, RequestGlobalLimit: 100, ConfirmGlobalLimit: 1000})
	f.login, err = tokenservice.NewNativeEmailLogin(f.primary, f.otp)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f nativeEmailFixture) request(t *testing.T, db *pgxpool.Pool, ctx context.Context) otpservice.ConfirmInput {
	t.Helper()
	requested, err := f.login.Request(ctx, f.email, "192.0.2.1", "orders", []accessdomain.PermissionKey{"orders.read"})
	if err != nil {
		t.Fatal(err)
	}
	var payload []byte
	if err := db.QueryRow(ctx, `SELECT payload FROM auth.email_login_outbox WHERE digest=$1`, f.cipher.Digest("native:binding:"+requested.Binding)).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	plain, err := f.cipher.Open(payload)
	if err != nil {
		t.Fatal(err)
	}
	var mail struct {
		Body string `json:"body"`
	}
	if err := json.Unmarshal(plain, &mail); err != nil {
		t.Fatal(err)
	}
	start := strings.Index(mail.Body, "<strong>") + len("<strong>")
	return otpservice.ConfirmInput{Binding: requested.Binding, Code: mail.Body[start : start+8], IP: "192.0.2.1", UserAgent: "native email fixture"}
}

func (f nativeEmailFixture) verify(t *testing.T, ctx context.Context, result *tokenservice.RefreshResult, mfa bool) authjwt.Claims {
	t.Helper()
	verifier, err := authjwt.NewVerifier(authjwt.Expectations{Issuer: "https://auth.example", Audience: "orders", Mode: authjwt.Strict}, f.keys, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	claims, err := verifier.VerifySignature(ctx, result.Raw, time.Now())
	methods := []string{"emailotp"}
	if mfa {
		methods = append(methods, "mfa")
	}
	if err != nil || claims.Subject != string(f.user) || !slices.Equal(claims.Methods, methods) || (claims.MFATime != nil) != mfa || claims.Scope != "orders.read" {
		t.Fatal("incorrect email assurance or target", err)
	}
	if _, err := f.tokens.Refresh(ctx, tokenservice.RefreshInput{Token: result.RefreshToken, IP: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	return claims
}

func checkNativeEmailOTP(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("real mail code parallel issuance refresh", func(t *testing.T) {
		f := newNativeEmailFixture(t, db, ctx)
		input := f.request(t, db, ctx)
		var wg sync.WaitGroup
		results := make(chan *tokenservice.NativeLoginResult, 8)
		for range 8 {
			wg.Go(func() {
				result, err := f.login.Confirm(ctx, input)
				if err != nil && !errors.Is(err, otpdomain.ErrInvalidCode) {
					t.Error(err)
				}
				results <- result
			})
		}
		wg.Wait()
		close(results)
		winners := 0
		for result := range results {
			if result != nil {
				winners++
				if result.Tokens == nil || result.Challenge != nil {
					t.Fatal("false MFA requirement")
				}
				assertNativeRows(t, db, ctx, string(f.user), 1)
				claims := f.verify(t, ctx, result.Tokens, false)
				var private bool
				if err := db.QueryRow(ctx, `SELECT password_verified_at IS NOT NULL OR credential_profile<>'api' FROM auth.sessions WHERE id=$1`, claims.SessionID).Scan(&private); err != nil || private {
					t.Fatal("private/browser authority leaked", err)
				}
			}
		}
		if winners != 1 {
			t.Fatal("not exactly one issuance", winners)
		}
	})
	t.Run("native five guesses committed", func(t *testing.T) {
		f := newNativeEmailFixture(t, db, ctx)
		input := f.request(t, db, ctx)
		bad := input
		bad.Code = "00000000"
		if bad.Code == input.Code {
			bad.Code = "00000001"
		}
		var wg sync.WaitGroup
		var failures atomic.Int64
		for range 8 {
			wg.Go(func() {
				if _, err := f.login.Confirm(ctx, bad); errors.Is(err, otpdomain.ErrInvalidCode) {
					failures.Add(1)
				} else {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		var attempts int
		if err := db.QueryRow(ctx, `SELECT attempts FROM auth.email_login_challenges WHERE user_id=$1`, f.user).Scan(&attempts); err != nil || attempts != 5 || failures.Load() != 8 {
			t.Fatal("wrong guess cap", attempts, err)
		}
		if _, err := f.login.Confirm(ctx, input); !errors.Is(err, otpdomain.ErrInvalidCode) {
			t.Fatal("exhausted challenge accepted", err)
		}
		assertNativeRows(t, db, ctx, string(f.user), 0)
	})
	checkNativeEmailGuards(t, db, ctx)
	checkNativeEmailMFA(t, db, ctx)
}
