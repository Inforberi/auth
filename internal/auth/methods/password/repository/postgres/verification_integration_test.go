package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

func checkVerification(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Helper()
	cipher, err := secretbox.New("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	repo := accountpostgres.New(db)
	mail := &verificationMail{}
	svc := accountservice.New(repo, verificationLimits{}, cipher, mail, accountservice.Config{URL: "https://example.com/verify", TTL: 30 * time.Minute, ResendInterval: time.Minute})
	var last domain.Verification
	prepare := func(ctx context.Context, tx pgx.Tx, user domain.UserID, id domain.AddressID, email string) error {
		prepared, err := svc.PrepareVerification(email)
		if err != nil {
			return err
		}
		last = prepared
		return repo.QueueInTransaction(ctx, tx, user, id, prepared)
	}
	password := NewWithRegistration(db, prepare)
	user, err := password.CreateUser(ctx, "verification@example.com", "hash")
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(svc.RequireVerified(ctx, user), domain.ErrEmailUnverified) {
		t.Fatal("unverified user accepted")
	}
	first := verificationToken(t, cipher, last)
	if err := svc.Resend(ctx, "verification@example.com", "ip"); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.email_verification_audit WHERE user_id=$1`, user).Scan(&count); err != nil || count != 1 {
		t.Fatal("cooldown was not respected", err)
	}
	if _, err := db.Exec(ctx, `UPDATE auth.user_emails SET verification_sent_at=now()-interval '2 minutes' WHERE user_id=$1`, user); err != nil {
		t.Fatal(err)
	}
	if err := svc.Resend(ctx, "verification@example.com", "ip"); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(svc.Confirm(ctx, first, "ip"), domain.ErrInvalidVerification) {
		t.Fatal("resend did not replace token")
	}
	job, err := repo.ClaimDelivery(ctx)
	if err != nil || job == nil {
		t.Fatal("delivery missing", err)
	}
	if another, err := repo.ClaimDelivery(ctx); err != nil || another != nil {
		t.Fatal("leased delivery claimed twice", err)
	}
	if err := repo.FinishDelivery(ctx, *job, false); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE auth.email_verification_outbox SET available_at=now() WHERE id=$1`, job.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeliverOne(ctx); err != nil || mail.sent != 1 {
		t.Fatal("retry failed", err)
	}
	plain, err := cipher.Open(job.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var message struct {
		To   string
		Link string
	}
	if err := json.Unmarshal(plain, &message); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(message.Link)
	if err != nil {
		t.Fatal(err)
	}
	token := u.Query().Get("token")
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Go(func() { results <- svc.Confirm(ctx, token, "ip") })
	}
	wg.Wait()
	close(results)
	accepted, rejected := 0, 0
	for err := range results {
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, domain.ErrInvalidVerification):
			rejected++
		default:
			t.Fatal(err)
		}
	}
	if accepted != 1 || rejected != 1 {
		t.Fatal("consume was not single-use", accepted, rejected)
	}
	if err := svc.RequireVerified(ctx, user); err != nil {
		t.Fatal(err)
	}
	if err := svc.Resend(ctx, "unknown@example.com", "ip"); err != nil {
		t.Fatal("unknown email enumerated", err)
	}
	if err := svc.Resend(ctx, "verification@example.com", "ip"); err != nil {
		t.Fatal("verified email enumerated", err)
	}
	if job, err := repo.ClaimDelivery(ctx); err != nil || job != nil {
		t.Fatal("ineligible email queued", err)
	}
	checkVerificationRollback(t, db, ctx, prepare)
	checkVerificationFailures(t, db, ctx, password, svc, repo, cipher, &last)
	checkVerificationExpiry(t, db, ctx, password, svc, cipher, &last)
}

func checkVerificationRollback(t *testing.T, db *pgxpool.Pool, ctx context.Context, prepare func(context.Context, pgx.Tx, domain.UserID, domain.AddressID, string) error) {
	t.Helper()
	repo := NewWithRegistration(db, func(ctx context.Context, tx pgx.Tx, user domain.UserID, id domain.AddressID, email string) error {
		if err := prepare(ctx, tx, user, id, email); err != nil {
			return err
		}
		return errors.New("intent write failed")
	})
	if _, err := repo.CreateUser(ctx, "rollback-verification@example.com", "hash"); err == nil {
		t.Fatal("registration committed after outbox failure")
	}
	var exists bool
	if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.user_emails WHERE email='rollback-verification@example.com')`).Scan(&exists); err != nil || exists {
		t.Fatal("registration was not rolled back", err)
	}
}

func checkVerificationExpiry(t *testing.T, db *pgxpool.Pool, ctx context.Context, password *PasswordRepo, svc *accountservice.Service, cipher *secretbox.Cipher, last *domain.Verification) {
	t.Helper()
	user, err := password.CreateUser(ctx, "expired-verification@example.com", "hash")
	if err != nil {
		t.Fatal(err)
	}
	token := verificationToken(t, cipher, *last)
	if _, err := db.Exec(ctx, `UPDATE auth.email_verifications SET created_at=now()-interval '1 hour',expires_at=clock_timestamp() WHERE digest=$1`, last.Digest); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(svc.Confirm(ctx, token, "ip"), domain.ErrInvalidVerification) {
		t.Fatal("expired token accepted")
	}
	if !errors.Is(svc.RequireVerified(ctx, user), domain.ErrEmailUnverified) {
		t.Fatal("expiry verified email")
	}
	if err := svc.DeliverOne(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := accountpostgres.New(db).PurgeRetention(ctx, retentionPolicy()); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.email_verification_outbox WHERE digest=$1`, last.Digest).Scan(&count); err != nil || count != 0 {
		t.Fatal("expired ciphertext retained", err)
	}
}

func verificationToken(t *testing.T, cipher *secretbox.Cipher, prepared domain.Verification) string {
	t.Helper()
	plain, err := cipher.Open(prepared.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var message struct{ Link string }
	if err := json.Unmarshal(plain, &message); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(message.Link)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("token")
}

type verificationMail struct{ sent int }

func (m *verificationMail) SendContext(context.Context, string, string, string) error {
	m.sent++
	return nil
}

type verificationLimits struct{}

func (verificationLimits) Allow(context.Context, string, int, time.Duration) (bool, error) {
	return true, nil
}
