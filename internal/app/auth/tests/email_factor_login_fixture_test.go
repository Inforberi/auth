package auth_test

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

type emailFactorLoginFixture struct {
	emailPreparationSQLFixture
	login *otpservice.EmailLogin
	proof mfaservice.PrimaryProof
}

func emailFactorLoginConfig() mfaservice.LoginConfig {
	return mfaservice.LoginConfig{
		ChallengeTTL: 5 * time.Minute, SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour,
		UserLimitPerMinute: 100, IPLimitPerMinute: 100, GlobalLimitPerMinute: 1000,
	}
}

func newEmailFactorLoginFixture(t *testing.T, db *pgxpool.Pool, ctx context.Context, name string) emailFactorLoginFixture {
	t.Helper()
	f, factors := preparedEmailFactor(t, db, ctx, "login-"+name, false)
	require.NoError(t, factors.Enable(ctx, f.proof))
	login, err := otpservice.NewEmailLogin(mfapostgres.New(db), f.cipher, recoveryCipher(t), mfaTestLimit{}, tokengenerate.New(), emailFactorLoginConfig())
	require.NoError(t, err)
	var role string
	require.NoError(t, db.QueryRow(ctx, `INSERT INTO auth.roles(key,name,mfa_required) VALUES($1,'Email MFA fixture',true) RETURNING id`, "email_"+strings.ReplaceAll(string(f.user), "-", "")).Scan(&role))
	accessExec(t, db, ctx, `INSERT INTO auth.role_permissions(role_id,permission_key) VALUES($1,'orders.read')`, role)
	accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) VALUES($1,$2)`, f.user, role)
	return emailFactorLoginFixture{
		emailPreparationSQLFixture: f, login: login,
		proof: mfaservice.PrimaryProof{UserID: f.user, AuthVersion: f.proof.AuthVersion + 1, Method: "password", Reference: "old-hash", VerifiedAt: time.Now().UTC()},
	}
}

func (f emailFactorLoginFixture) code(t *testing.T, db *pgxpool.Pool, ctx context.Context, challenge *mfalogin.LoginChallenge) mfalogin.CompleteLoginInput {
	t.Helper()
	var payload []byte
	require.NoError(t, db.QueryRow(ctx, `SELECT o.payload FROM auth.email_login_outbox o JOIN auth.email_login_challenges c ON c.digest=o.digest
 WHERE c.user_id=$1 AND c.purpose='mfa_email_login'`, f.user).Scan(&payload))
	plain, err := f.cipher.Open(payload)
	require.NoError(t, err)
	defer clear(plain)
	var mail struct{ To, Body string }
	require.NoError(t, json.Unmarshal(plain, &mail))
	require.Equal(t, f.email, mail.To)
	code := regexp.MustCompile(`<strong>([0-9]{8})</strong>`).FindStringSubmatch(mail.Body)
	require.Len(t, code, 2)
	return mfalogin.CompleteLoginInput{Token: challenge.Token, Binding: challenge.Binding, Code: code[1], UserAgent: "email factor fixture", IP: "192.0.2.1"}
}

func (f emailFactorLoginFixture) start(t *testing.T, db *pgxpool.Pool, ctx context.Context) mfalogin.CompleteLoginInput {
	t.Helper()
	challenge, err := f.login.Start(ctx, f.proof, "192.0.2.1")
	require.NoError(t, err)
	require.False(t, challenge.EnrollmentRequired)
	require.False(t, challenge.RecoveryRequired)
	return f.code(t, db, ctx, challenge)
}
