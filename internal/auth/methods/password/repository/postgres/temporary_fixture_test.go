package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type temporaryFixtureHash struct{}

func (temporaryFixtureHash) GenerateHash(_ context.Context, raw []byte) (string, error) {
	digest := sha256.Sum256(raw)
	return "test-only:" + hex.EncodeToString(digest[:]), nil
}

func (temporaryFixtureHash) Compare(_ context.Context, raw, hash string) error {
	digest := sha256.Sum256([]byte(raw))
	if hash != "test-only:"+hex.EncodeToString(digest[:]) {
		return errors.New("incorrect password")
	}
	return nil
}

type temporaryFixture struct {
	service  *passwordservice.TemporaryPasswordService
	repo     *TemporaryPasswordRepo
	accounts *accountpostgres.Repository
	input    passwordservice.TemporaryProvisionInput
}

func newTemporaryFixture(t *testing.T, db *pgxpool.Pool, ctx context.Context, name string) temporaryFixture {
	t.Helper()
	actor, err := New(db).CreateUser(ctx, "temporary-actor-"+name+"@example.com", "actor-hash")
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := secretbox.NewScoped("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "password-reset:v1")
	if err != nil {
		t.Fatal(err)
	}
	accounts := accountpostgres.NewWithDelivery(db, false, true)
	repo := NewTemporaryPassword(db, accounts.ProvisionInTransaction)
	limit := passwordservice.NewLoginLimit(verificationLimits{}, cipher, passwordservice.CapacityConfig{LoginIPLimit: 30, LoginEmailLimit: 10, LoginGlobalLimit: 1000})
	cfg := passwordservice.TemporaryPasswordConfig{Enabled: true, TTL: time.Hour, SetupTTL: 5 * time.Minute, ReissueCooldown: time.Minute, IssueActorAttemptsPerMinute: 30, IssueProjectAttemptsPerMinute: 100, SetupProjectAttemptsPerMinute: 100}
	return temporaryFixture{
		service: passwordservice.NewTemporaryPassword(repo, temporaryFixtureHash{}, verificationLimits{}, cipher.Digest, limit, cfg), repo: repo, accounts: accounts,
		input: passwordservice.TemporaryProvisionInput{ActorID: actor, IdempotencyKey: temporaryRequestKey(t, db, ctx), Email: "temporary-" + name + "@example.com"},
	}
}

func temporaryRequestKey(t *testing.T, db *pgxpool.Pool, ctx context.Context) string {
	t.Helper()
	var key string
	if err := db.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&key); err != nil {
		t.Fatal(err)
	}
	return key
}

func (f temporaryFixture) create(t *testing.T, ctx context.Context) *passwordservice.TemporaryIssueResult {
	t.Helper()
	result, err := f.service.Provision(ctx, f.input)
	if err != nil || result.Password == "" {
		t.Fatal("temporary provisioning", result, err)
	}
	return result
}

func (f temporaryFixture) login(t *testing.T, ctx context.Context, secret string) *passwordservice.TemporaryLoginResult {
	t.Helper()
	result, err := f.service.Login(ctx, f.input.Email, secret, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func temporaryTokenDigest(raw string) string {
	digest := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(digest[:])
}

func allowTemporaryReissue(t *testing.T, db *pgxpool.Pool, ctx context.Context, user accountdomain.UserID) {
	t.Helper()
	if _, err := db.Exec(ctx, `UPDATE auth.account_provisions SET temporary_password_issued_at=clock_timestamp()-interval '2 minutes' WHERE user_id=$1`, user); err != nil {
		t.Fatal(err)
	}
}

func assertTemporaryState(t *testing.T, db *pgxpool.Pool, ctx context.Context, user accountdomain.UserID, pending bool) {
	t.Helper()
	var status string
	var required, verified, permanent, temporary bool
	if err := db.QueryRow(ctx, `SELECT u.status,p.password_change_required,e.verified_at IS NOT NULL,
		EXISTS(SELECT 1 FROM auth.password_credentials pc WHERE pc.user_id=u.id),
		EXISTS(SELECT 1 FROM auth.temporary_password_credentials pc WHERE pc.user_id=u.id)
		FROM auth.users u JOIN auth.account_provisions p ON p.user_id=u.id JOIN auth.user_emails e ON e.id=p.invitation_email_id WHERE u.id=$1`, user).
		Scan(&status, &required, &verified, &permanent, &temporary); err != nil {
		t.Fatal(err)
	}
	if required != pending || temporary != pending || permanent == pending || verified || (pending && status != "pending") || (!pending && status != "active") {
		t.Fatal("unexpected temporary state", status, required, verified, permanent, temporary)
	}
}
