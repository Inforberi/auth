package postgres

import (
	"context"
	"encoding/json"
	"regexp"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	otppostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/repository/postgres"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

const preparationPurpose = "mfa-email-prepare:"

type emailPreparationSQLFixture struct {
	statusFixture
	proof   mfaservice.Proof
	service *otpservice.EmailPreparation
	repo    *otppostgres.Repository
	cipher  *secretbox.Cipher
}

func newEmailPreparationFixture(t *testing.T, db *pgxpool.Pool, ctx context.Context, name string, strong bool) emailPreparationSQLFixture {
	t.Helper()
	var base statusFixture
	var proof mfaservice.Proof
	if strong {
		f := newMFALoginFixture(t, db, ctx, "email-preparation-"+name)
		base, proof = f.statusFixture, managementProof(t, ctx, f)
	} else {
		base = newStatusFixture(t, db, ctx, "email-preparation-"+name)
		tokens := tokengenerate.New()
		hash := tokens.Hash("fresh-preparation-" + string(base.user))
		_, err := base.sessions.ConfirmPassword(ctx, base.user, base.params.TokenHash, "old-hash", 1, hash)
		require.NoError(t, err)
		proof = mfaservice.Proof{UserID: base.user, TokenHash: hash, AuthVersion: 1}
	}
	accessExec(t, db, ctx, `UPDATE auth.user_emails SET verified_at=clock_timestamp() WHERE user_id=$1`, base.user)
	cipher, err := secretbox.NewScoped("bG9jYWwtb25seS1hdXRoLW91dGJveC1rZXktMzJieXQ=", "email-login:v1")
	require.NoError(t, err)
	repo := otppostgres.New(db)
	svc, err := otpservice.NewEmailPreparation(repo, cipher, mfaTestLimit{}, tokengenerate.New(), otpservice.EmailPreparationConfig{TTL: 5 * time.Minute, ResendInterval: time.Minute, RequestsPerMinute: 100, ConfirmationsPerMinute: 1000})
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, err := db.Exec(cleanup, `DELETE FROM auth.email_login_challenges WHERE user_id=$1`, base.user)
		require.NoError(t, err)
	})
	return emailPreparationSQLFixture{statusFixture: base, proof: proof, service: svc, repo: repo, cipher: cipher}
}

func (f emailPreparationSQLFixture) request(t *testing.T, db *pgxpool.Pool, ctx context.Context) otpservice.EmailPreparationConfirmation {
	t.Helper()
	requested, err := f.service.Request(ctx, f.proof, f.email, "192.0.2.1")
	require.NoError(t, err)
	var payload []byte
	require.NoError(t, db.QueryRow(ctx, `SELECT payload FROM auth.email_login_outbox WHERE digest=$1`, f.cipher.Digest(preparationPurpose+"binding:"+requested.Binding)).Scan(&payload))
	plain, err := f.cipher.Open(payload)
	require.NoError(t, err)
	defer clear(plain)
	var mail struct{ To, Body string }
	require.NoError(t, json.Unmarshal(plain, &mail))
	require.Equal(t, f.email, mail.To)
	code := regexp.MustCompile(`<strong>([0-9]{8})</strong>`).FindStringSubmatch(mail.Body)
	require.Len(t, code, 2)
	return otpservice.EmailPreparationConfirmation{Proof: f.proof, Binding: requested.Binding, Code: code[1], IP: "192.0.2.1"}
}

func (f emailPreparationSQLFixture) cloneSession(t *testing.T, db *pgxpool.Pool, ctx context.Context, profile string) mfaservice.Proof {
	t.Helper()
	raw, err := tokengenerate.New().GenerateToken()
	require.NoError(t, err)
	proof := f.proof
	proof.TokenHash = tokengenerate.New().Hash(raw)
	_, err = db.Exec(ctx, `INSERT INTO auth.sessions(credential_profile,token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,
 primary_method,primary_verified_at,password_verified_at,mfa_verified_at,mfa_method,user_agent,ip_address)
 SELECT $3,$2,user_id,auth_version,created_at,expires_at,absolute_expires_at,primary_method,primary_verified_at,
 password_verified_at,mfa_verified_at,mfa_method,'preparation second session','192.0.2.2' FROM auth.sessions WHERE token_hash=$1`, f.proof.TokenHash, proof.TokenHash, profile)
	require.NoError(t, err)
	return proof
}
