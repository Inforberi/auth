package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type invitationTestHasher struct{}

func (invitationTestHasher) GenerateHash(context.Context, []byte) (string, error) {
	return "invitation-hash", nil
}

func (invitationTestHasher) Compare(context.Context, string, string) error {
	return errors.New("compare not expected")
}

type invitationFixture struct {
	accounts   *accountpostgres.Repository
	provision  *accountservice.ProvisionService
	activation *passwordservice.ActivationService
	cipher     *secretbox.Cipher
	input      accountservice.ProvisionInput
}

func newInvitationFixture(t *testing.T, db *pgxpool.Pool, ctx context.Context, name string) invitationFixture {
	t.Helper()
	actor := provisioningPrincipal(t, db, ctx)
	var key string
	if err := db.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&key); err != nil {
		t.Fatal(err)
	}
	cipher, err := secretbox.New("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	repo := accountpostgres.NewWithDelivery(db, accountpostgres.DeliveryConfig{Invitations: true})
	account := accountservice.New(repo, verificationLimits{}, cipher, nil, accountservice.Config{})
	cfg := accountservice.InvitationConfig{Enabled: true, URL: "https://app.example.com/activate", TTL: 24 * time.Hour, ActivationGlobalLimit: 100}
	recovery := passwordservice.NewRecovery(nil, cipher, verificationLimits{}, nil, invitationTestHasher{}, passwordservice.Config{})
	return invitationFixture{
		accounts: repo, provision: accountservice.NewProvisioning(repo, account, cfg), activation: passwordservice.NewActivation(repo, recovery, cfg), cipher: cipher,
		input: accountservice.ProvisionInput{Actor: actor, IdempotencyKey: key, Email: "invited-" + name + "@example.com", Invite: true},
	}
}

func provisioningPrincipal(t *testing.T, db *pgxpool.Pool, ctx context.Context) accessservice.Principal {
	t.Helper()
	actor := accessPrincipal(t, db, ctx)
	// Synthetic current password/MFA proofs are provided by accessPrincipal, not a login bypass in runtime.
	accessExec(t, db, ctx, `WITH role AS (
		INSERT INTO auth.roles(key,name) VALUES('provision_operator','Provision operator')
		ON CONFLICT(key) DO UPDATE SET name=EXCLUDED.name RETURNING id
	), permission AS (
		INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,'accounts.users.manage' FROM role ON CONFLICT DO NOTHING
	) INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM role`, actor.UserID)
	return actor
}

func (f invitationFixture) create(t *testing.T, db *pgxpool.Pool, ctx context.Context) (accountdomain.UserID, string, string) {
	t.Helper()
	result, err := f.provision.Provision(ctx, f.input)
	if err != nil {
		t.Fatal(err)
	}
	var digest string
	var payload []byte
	if err := db.QueryRow(ctx, `SELECT i.digest,o.payload FROM auth.account_invitations i JOIN auth.invitation_outbox o ON o.digest=i.digest WHERE i.user_id=$1`, result.UserID).Scan(&digest, &payload); err != nil {
		t.Fatal(err)
	}
	plain, err := f.cipher.Open(payload)
	if err != nil {
		t.Fatal(err)
	}
	var message struct{ Body string }
	if err := json.Unmarshal(plain, &message); err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`#token=([A-Za-z0-9_-]+)`).FindStringSubmatch(message.Body)
	if len(match) != 2 {
		t.Fatal("missing activation token")
	}
	return result.UserID, digest, match[1]
}

func checkInvitations(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("provision-and-activate", func(t *testing.T) {
		f := newInvitationFixture(t, db, ctx, "basic")
		user, digest, token := f.create(t, db, ctx)
		assertInvitationState(t, db, ctx, user, "pending", false, true)
		reused, err := f.provision.Provision(ctx, f.input)
		if err != nil || !reused.Reused || reused.UserID != user {
			t.Fatal("idempotency", reused, err)
		}
		changed := f.input
		changed.Invite = false
		if _, err := f.provision.Provision(ctx, changed); !errors.Is(err, accountdomain.ErrProvisionConflict) {
			t.Fatal("changed command", err)
		}
		duplicate := f.input
		duplicate.IdempotencyKey = "00000000-0000-4000-8000-000000000001"
		if _, err := f.provision.Provision(ctx, duplicate); !errors.Is(err, accountdomain.ErrProvisionEmailExists) {
			t.Fatal("email auto-merged", err)
		}
		if err := New(db).ConsumeReset(ctx, digest, "other-hash"); err == nil {
			t.Fatal("invitation accepted as reset")
		}
		if err := f.accounts.Confirm(ctx, digest); err == nil {
			t.Fatal("invitation accepted as verification")
		}
		if err := f.activation.Activate(ctx, token, "ExamplePass2", "ExamplePass2", "ip"); err != nil {
			t.Fatal(err)
		}
		assertInvitationState(t, db, ctx, user, "active", true, false)
		if err := f.activation.Activate(ctx, token, "OtherExamplePass2", "OtherExamplePass2", "ip"); !errors.Is(err, accountdomain.ErrInvalidInvitation) {
			t.Fatal("replay", err)
		}
		reused, err = f.provision.Provision(ctx, f.input)
		if err != nil || reused.UserID != user {
			t.Fatal("activation changed idempotency", err)
		}
		var invitations int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.account_invitations WHERE user_id=$1`, user).Scan(&invitations); err != nil || invitations != 0 {
			t.Fatal("replay recreated invitation", err)
		}
	})
	t.Run("bare-account", func(t *testing.T) {
		f := newInvitationFixture(t, db, ctx, "bare")
		f.input.Email = ""
		f.input.Invite = false
		result, err := f.provision.Provision(ctx, f.input)
		if err != nil {
			t.Fatal(err)
		}
		assertInvitationState(t, db, ctx, result.UserID, "pending", false, false)
	})
	t.Run("concurrent-acceptance", func(t *testing.T) {
		f := newInvitationFixture(t, db, ctx, "concurrent")
		user, digest, _ := f.create(t, db, ctx)
		results := make(chan error, 16)
		for range 16 {
			go func() { results <- f.accounts.ActivateInvitation(ctx, digest, "new-hash") }()
		}
		accepted := 0
		for range 16 {
			err := <-results
			if err == nil {
				accepted++
			} else if !errors.Is(err, accountdomain.ErrInvalidInvitation) {
				t.Fatal(err)
			}
		}
		if accepted != 1 {
			t.Fatal("accepted", accepted)
		}
		assertInvitationState(t, db, ctx, user, "active", true, false)
	})
	t.Run("concurrent-provision", func(t *testing.T) {
		f := newInvitationFixture(t, db, ctx, "commands")
		results := make(chan *accountservice.ProvisionResult, 16)
		failures := make(chan error, 16)
		for range 16 {
			go func() { result, err := f.provision.Provision(ctx, f.input); results <- result; failures <- err }()
		}
		var user accountdomain.UserID
		created := 0
		for range 16 {
			result := <-results
			if err := <-failures; err != nil {
				t.Fatal(err)
			}
			if user != "" && user != result.UserID {
				t.Fatal("different UUIDs")
			}
			user = result.UserID
			if !result.Reused {
				created++
			}
		}
		if created != 1 {
			t.Fatal("created", created)
		}
	})
	for _, name := range []string{"expired", "blocked", "deleted", "version"} {
		t.Run(name, func(t *testing.T) {
			f := newInvitationFixture(t, db, ctx, name)
			user, digest, _ := f.create(t, db, ctx)
			var err error
			switch name {
			case "expired":
				_, err = db.Exec(ctx, `UPDATE auth.account_invitations SET expires_at=clock_timestamp()-interval '1 second' WHERE digest=$1`, digest)
			case "version":
				_, err = db.Exec(ctx, `UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`, user)
			case "blocked":
				_, err = f.accounts.ChangeStatus(ctx, accountdomain.StatusChange{UserID: user, ActorID: f.input.Actor.UserID, Status: accountdomain.StatusBlocked, ExpectedVersion: 1})
			case "deleted":
				_, err = f.accounts.DeleteAccount(ctx, accountdomain.AccountDeletion{UserID: user, ActorID: f.input.Actor.UserID, ExpectedVersion: 1})
			}
			if err != nil {
				t.Fatal(err)
			}
			if name == "blocked" {
				_, err := f.accounts.ChangeStatus(ctx, accountdomain.StatusChange{UserID: user, ActorID: f.input.Actor.UserID, Status: accountdomain.StatusActive, ExpectedVersion: 2})
				if !errors.Is(err, accountdomain.ErrAccountConflict) {
					t.Fatal("unblock bypassed activation", err)
				}
			}
			if err := f.accounts.CheckInvitation(ctx, digest); !errors.Is(err, accountdomain.ErrInvalidInvitation) {
				t.Fatal("preflight", err)
			}
			if err := f.accounts.ActivateInvitation(ctx, digest, "new-hash"); !errors.Is(err, accountdomain.ErrInvalidInvitation) {
				t.Fatal("consumption", err)
			}
		})
	}
	t.Run("audit-rollback", func(t *testing.T) {
		f := newInvitationFixture(t, db, ctx, "rollback")
		user, digest, _ := f.create(t, db, ctx)
		if _, err := db.Exec(ctx, `ALTER TABLE auth.invitation_audit ADD CONSTRAINT fixture_invitation_audit_fail CHECK(action<>'activated') NOT VALID`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_, err := db.Exec(ctx, `ALTER TABLE auth.invitation_audit DROP CONSTRAINT fixture_invitation_audit_fail`)
			if err != nil {
				t.Error(err)
			}
		}()
		if err := f.accounts.ActivateInvitation(ctx, digest, "new-hash"); err == nil {
			t.Fatal("missing rollback")
		}
		assertInvitationState(t, db, ctx, user, "pending", false, true)
	})
	t.Run("pending-cannot-unblock", func(t *testing.T) {
		f := newInvitationFixture(t, db, ctx, "bypass")
		user, _, _ := f.create(t, db, ctx)
		_, err := f.accounts.ChangeStatus(ctx, accountdomain.StatusChange{UserID: user, ActorID: f.input.Actor.UserID, Status: accountdomain.StatusActive, ExpectedVersion: 1})
		if !errors.Is(err, accountdomain.ErrAccountConflict) {
			t.Fatal("status bypassed activation", err)
		}
	})
}

func assertInvitationState(t *testing.T, db *pgxpool.Pool, ctx context.Context, user accountdomain.UserID, status string, activated, invited bool) {
	t.Helper()
	var state string
	var credential, verified, invitation bool
	var sessions int
	err := db.QueryRow(ctx, `SELECT status,EXISTS(SELECT 1 FROM auth.password_credentials WHERE user_id=u.id),
		EXISTS(SELECT 1 FROM auth.user_emails WHERE user_id=u.id AND verified_at IS NOT NULL),
		EXISTS(SELECT 1 FROM auth.account_invitations WHERE user_id=u.id),
		(SELECT count(*) FROM auth.sessions WHERE user_id=u.id) FROM auth.users u WHERE id=$1`, user).Scan(&state, &credential, &verified, &invitation, &sessions)
	if err != nil || state != status || credential != activated || verified != activated || invitation != invited || sessions != 0 {
		t.Fatal("unexpected activation state", state, credential, verified, invitation, sessions, err)
	}
}
