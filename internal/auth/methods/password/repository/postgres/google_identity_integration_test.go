package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	googledomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/google/domain"
	telegramdomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/domain"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func checkGoogleIdentity(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	f, management := identityManagementFixture(t, db, ctx, "google")
	google := accountdomain.IdentityKey{Issuer: googledomain.Issuer, Subject: "shared-provider-subject"}
	telegram := accountdomain.IdentityKey{Issuer: telegramdomain.Issuer, Subject: google.Subject}
	for _, key := range []accountdomain.IdentityKey{google, telegram} {
		if err := management.Link(ctx, f.user, f.params.TokenHash, key); err != nil {
			t.Fatal("independent provider link", err)
		}
	}
	resolver := accountservice.NewIdentityResolution(f.accounts)
	user, err := resolver.Resolve(ctx, google, false)
	if err != nil || user.ID != f.user {
		t.Fatal("Google link changed owner", user, err)
	}
	other, otherManagement := identityManagementFixture(t, db, ctx, "google-other")
	if err := otherManagement.Link(ctx, other.user, other.params.TokenHash, google); !errors.Is(err, accountdomain.ErrIdentityConflict) {
		t.Fatal("Google foreign ownership", err)
	}
	second := google
	second.Subject = "another-google-subject"
	if err := management.Link(ctx, f.user, f.params.TokenHash, second); !errors.Is(err, accountdomain.ErrIdentityConflict) {
		t.Fatal("multiple Google accounts on owner", err)
	}
	if _, err := resolver.Resolve(ctx, second, false); !errors.Is(err, accountdomain.ErrIdentityNotFound) {
		t.Fatal("failed link left identity", err)
	}
	if err := management.Unlink(ctx, f.user, f.params.TokenHash, google.Issuer); err != nil {
		t.Fatal(err)
	}
	if _, err := f.sessions.FindSession(ctx, f.params.TokenHash); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatal("Google unlink did not revoke sessions", err)
	}
	if _, err := resolver.Resolve(ctx, google, false); !errors.Is(err, accountdomain.ErrIdentityNotFound) {
		t.Fatal("Google unlink preserved identity", err)
	}
	remaining, err := resolver.Resolve(ctx, telegram, false)
	if err != nil || remaining.ID != f.user || remaining.AuthVersion != 2 {
		t.Fatal("Google unlink affected Telegram ownership", remaining, err)
	}

	// Another provider's row is not sufficient to authorize unlink without a usable password method.
	if err := otherManagement.Link(ctx, other.user, other.params.TokenHash, second); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, "DELETE FROM auth.password_credentials WHERE user_id=$1", other.user); err != nil {
		t.Fatal(err)
	}
	if err := otherManagement.Unlink(ctx, other.user, other.params.TokenHash, second.Issuer); !errors.Is(err, accountdomain.ErrLastLoginMethod) {
		t.Fatal("unlink without remaining usable method", err)
	}

	key := accountdomain.IdentityKey{Issuer: googledomain.Issuer, Subject: "new-google-owner"}
	created, err := resolver.Resolve(ctx, key, true)
	if err != nil {
		t.Fatal(err)
	}
	sessions := sessionservice.New(clock.UTCClock{}, f.sessions, tokengenerate.New(), sessionservice.Config{SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour})
	issued, err := sessions.CreateSessionAtVersion(ctx, created.ID, "browser", "127.0.0.1", int64(created.AuthVersion))
	if err != nil {
		t.Fatal("Google common session", err)
	}
	if _, err := f.sessions.FindSession(ctx, tokengenerate.New().Hash(issued.RawToken)); err != nil {
		t.Fatal(err)
	}
	var contacts, credentials int
	if err := db.QueryRow(ctx, "SELECT (SELECT count(*) FROM auth.user_emails WHERE user_id=$1),(SELECT count(*) FROM auth.password_credentials WHERE user_id=$1)", created.ID).Scan(&contacts, &credentials); err != nil || contacts != 0 || credentials != 0 {
		t.Fatal("Google invented email/password", contacts, credentials, err)
	}
}
