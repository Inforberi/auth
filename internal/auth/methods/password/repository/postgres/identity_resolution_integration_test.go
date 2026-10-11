package postgres

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
)

func checkIdentityResolution(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	repo := accountpostgres.New(db)
	resolver := accountservice.NewIdentityResolution(repo)
	key := accountdomain.IdentityKey{Issuer: "https://identity.example", Subject: "External-Subject"}
	if user, err := resolver.Resolve(ctx, key, false); user != nil || !errors.Is(err, accountdomain.ErrIdentityNotFound) {
		t.Fatal("registration disabled created account", user, err)
	}
	var baseline int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.users`).Scan(&baseline); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	owners := make(chan accountdomain.UserID, 16)
	start := make(chan struct{})
	for range 16 {
		wg.Go(func() {
			<-start
			user, err := resolver.Resolve(ctx, key, true)
			if err != nil {
				t.Error(err)
				return
			}
			owners <- user.ID
		})
	}
	close(start)
	wg.Wait()
	close(owners)
	if len(owners) != 16 {
		t.Fatal("concurrent resolution failed", len(owners))
	}
	owner := <-owners
	for got := range owners {
		if got != owner {
			t.Fatal("identity split between accounts")
		}
	}
	var total, contacts, credentials, profiles int
	if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM auth.users),
		(SELECT count(*) FROM auth.user_emails WHERE user_id=$1),
		(SELECT count(*) FROM auth.password_credentials WHERE user_id=$1),
		(SELECT count(*) FROM auth.user_profile WHERE user_id=$1)`, owner).Scan(&total, &contacts, &credentials, &profiles); err != nil ||
		total != baseline+1 || contacts != 0 || credentials != 0 || profiles != 1 {
		t.Fatal("orphan users or invented email/credentials", total, contacts, credentials, profiles, err)
	}
	if user, err := resolver.Resolve(ctx, key, false); err != nil || user.ID != owner || user.AuthVersion != 1 {
		t.Fatal("existing identity requires registration", user, err)
	}
	for _, other := range []accountdomain.IdentityKey{
		{Issuer: key.Issuer, Subject: "external-subject"},
		{Issuer: "https://other-identity.example", Subject: key.Subject},
		{Issuer: "https://IDENTITY.example", Subject: key.Subject},
	} {
		if user, err := resolver.Resolve(ctx, other, true); err != nil || user.ID == owner {
			t.Fatal("issuer/subject incorrectly merged", user, err)
		}
	}
	if _, err := repo.ResolveIdentityAccount(ctx, accountdomain.IdentityKey{Issuer: key.Issuer, Subject: strings.Repeat("s", 256)}, true); err == nil {
		t.Fatal("SQL bound bypassed")
	}
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.users`).Scan(&total); err != nil || total != baseline+4 {
		t.Fatal("failed transaction left orphan user", total, err)
	}
	change := accountdomain.StatusChange{UserID: owner, ActorID: owner, Status: accountdomain.StatusBlocked, ExpectedVersion: 1}
	if _, err := accountservice.NewStatus(repo).Change(ctx, change); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(ctx, key, true); !errors.Is(err, accountdomain.ErrIdentityUnavailable) {
		t.Fatal("blocked identity recreated", err)
	}
	change.Status, change.ExpectedVersion = accountdomain.StatusActive, 2
	if _, err := accountservice.NewStatus(repo).Change(ctx, change); err != nil {
		t.Fatal(err)
	}
	if user, err := resolver.Resolve(ctx, key, false); err != nil || user.ID != owner || user.AuthVersion != 3 {
		t.Fatal("unblock lost identity/current version", user, err)
	}
	if _, err := accountservice.NewDeletion(repo).Delete(ctx, accountdomain.AccountDeletion{UserID: owner, ActorID: owner, ExpectedVersion: 3}); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(ctx, key, true); !errors.Is(err, accountdomain.ErrIdentityUnavailable) {
		t.Fatal("deleted identity recreated", err)
	}
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.linked_identities WHERE issuer=$1 AND subject=$2 AND user_id=$3`, key.Issuer, key.Subject, owner).Scan(&total); err != nil || total != 1 {
		t.Fatal("deletion released identity ownership", total, err)
	}
}
