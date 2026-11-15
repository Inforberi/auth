package auth_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	provisioning "github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/service"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	passwordprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/provisioning/service"
	passwordpostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/postgres"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
)

func TestPlatformUserLifecycleReceipt(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	f := newStatusFixture(t, db, ctx, "platform-lifecycle")
	command := accountpostgres.PlatformLifecycle{
		OperationID: "11000000-0000-4000-8000-000000000001",
		RealmID:     "11000000-0000-4000-8000-000000000002",
		ProjectID:   "11000000-0000-4000-8000-000000000003",
		ActorID:     "11000000-0000-4000-8000-000000000004",
		UserID:      f.user, Action: "blocked", ExpectedVersion: 1,
	}
	apply := func() (accountdomain.AuthVersion, error) {
		t.Helper()
		var result accountdomain.AuthVersion
		err := pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
			var err error
			result, err = accountpostgres.ApplyPlatformLifecycle(ctx, tx, command)
			return err
		})
		return result, err
	}
	for range 2 {
		version, err := apply()
		require.NoError(t, err)
		require.EqualValues(t, 2, version)
	}
	_, err := f.sessions.FindSession(ctx, f.params.TokenHash)
	require.True(t, errors.Is(err, sessiondomain.ErrSessionNotFound))
	command.Action = "delete"
	_, err = apply()
	require.ErrorIs(t, err, accountdomain.ErrAccountConflict)
}

func TestPlatformTemporaryPasswordProvision(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	command := accountpostgres.PlatformCreation{
		OperationID: "13000000-0000-4000-8000-000000000001",
		RealmID:     "13000000-0000-4000-8000-000000000002",
		ProjectID:   "13000000-0000-4000-8000-000000000003",
		ActorID:     "13000000-0000-4000-8000-000000000004",
		Temporary: passwordprovisioning.PreparedTemporaryPassword{
			Email: "platform-temporary@example.test", Fingerprint: strings.Repeat("c", 64), TTL: time.Hour,
			Credential: passworddomain.TemporaryCredential{PasswordHash: "fixture-hash", SecretDigest: strings.Repeat("d", 64)},
		},
	}
	create := func() accountdomain.UserID {
		t.Helper()
		command.TemporaryResult = &passwordprovisioning.TemporaryIssueResult{}
		var user accountdomain.UserID
		require.NoError(t, pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
			var err error
			user, err = accountpostgres.CreatePlatformUser(ctx, tx, command)
			return err
		}))
		return user
	}
	user := create()
	t.Cleanup(func() {
		_, err := db.Exec(ctx, `DELETE FROM auth.account_provisions WHERE platform_operation_id=$1`, command.OperationID)
		require.NoError(t, err)
	})
	require.False(t, command.TemporaryResult.Reused)
	require.False(t, command.TemporaryResult.ExpiresAt.IsZero())
	require.Equal(t, user, create())
	require.True(t, command.TemporaryResult.Reused)
	require.True(t, command.TemporaryResult.ExpiresAt.IsZero())
	repo := passwordpostgres.NewTemporaryPassword(db, nil)
	credential, err := repo.FindTemporary(ctx, command.Temporary.Email)
	require.NoError(t, err)
	require.Equal(t, user, credential.UserID)
	_, err = repo.BeginTemporary(ctx, *credential, strings.Repeat("e", 64), 10*time.Minute)
	require.NoError(t, err)
	reissue := accountpostgres.PlatformLifecycle{
		OperationID: "13000000-0000-4000-8000-000000000005", RealmID: command.RealmID,
		ProjectID: command.ProjectID, ActorID: command.ActorID, UserID: user,
		Action: "temporary_password", ExpectedVersion: 1, Temporary: command.Temporary,
	}
	reissue.Temporary.Credential.PasswordHash = "second-fixture-hash"
	for _, replay := range []bool{false, true} {
		reissue.TemporaryResult = &passwordprovisioning.TemporaryIssueResult{}
		require.NoError(t, pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
			version, err := accountpostgres.ApplyPlatformLifecycle(ctx, tx, reissue)
			if err == nil {
				require.EqualValues(t, 2, version)
			}
			return err
		}))
		require.Equal(t, replay, reissue.TemporaryResult.Reused)
	}
	require.ErrorIs(t, repo.CompleteTemporary(ctx, strings.Repeat("e", 64), "new-hash"), passworddomain.ErrInvalidTemporaryPassword)
	credential, err = repo.FindTemporary(ctx, command.Temporary.Email)
	require.NoError(t, err)
	require.Equal(t, "second-fixture-hash", credential.PasswordHash)
	_, err = repo.BeginTemporary(ctx, *credential, strings.Repeat("f", 64), 10*time.Minute)
	require.NoError(t, err)
	require.NoError(t, repo.CompleteTemporary(ctx, strings.Repeat("f", 64), "new-hash"))
	var verified bool
	require.NoError(t, db.QueryRow(ctx, `SELECT verified_at IS NOT NULL FROM auth.user_emails WHERE user_id=$1`, user).Scan(&verified))
	require.False(t, verified)
}

func TestPlatformUserCreationReceipt(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	command := accountpostgres.PlatformCreation{
		OperationID: "12000000-0000-4000-8000-000000000001",
		RealmID:     "12000000-0000-4000-8000-000000000002",
		ProjectID:   "12000000-0000-4000-8000-000000000003",
		ActorID:     "12000000-0000-4000-8000-000000000004",
		Invitation: provisioning.ProvisionCommand{
			Input:       provisioning.ProvisionInput{Email: "platform-invite@example.test", Invite: true},
			Fingerprint: strings.Repeat("a", 64),
			Invitation:  accountdomain.Invitation{Digest: accountservice.TokenDigest("fixture"), Payload: []byte("encrypted fixture")},
			TTL:         time.Hour,
		},
	}
	create := func() (accountdomain.UserID, error) {
		t.Helper()
		var user accountdomain.UserID
		err := pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
			var err error
			user, err = accountpostgres.CreatePlatformUser(ctx, tx, command)
			return err
		})
		return user, err
	}
	user, err := create()
	require.NoError(t, err)
	replay, err := create()
	require.NoError(t, err)
	require.Equal(t, user, replay)
	var pending bool
	require.NoError(t, db.QueryRow(ctx, `SELECT status='pending' FROM auth.users u JOIN auth.user_profile p ON p.user_id=u.id WHERE u.id=$1`, user).Scan(&pending))
	require.True(t, pending)
	var deliveries int
	require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.account_invitations i JOIN auth.invitation_outbox o USING(digest) WHERE i.user_id=$1`, user).Scan(&deliveries))
	require.Equal(t, 1, deliveries)
	command.Invitation.Fingerprint = strings.Repeat("b", 64)
	_, err = create()
	require.ErrorIs(t, err, accountdomain.ErrAccountConflict)
	command.Invitation.Fingerprint = strings.Repeat("a", 64)
	command.ActorID = "12000000-0000-4000-8000-000000000005"
	_, err = create()
	require.ErrorIs(t, err, accountdomain.ErrAccountConflict)

	accounts := accountpostgres.New(db)
	digest := command.Invitation.Invitation.Digest
	require.NoError(t, accounts.ActivateInvitation(ctx, digest, "activated-hash"))
	require.ErrorIs(t, accounts.CheckInvitation(ctx, digest), accountdomain.ErrInvalidInvitation)
}

func TestPlatformInitialEmail(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	command := accountpostgres.PlatformCreation{
		OperationID: "14000000-0000-4000-8000-000000000001", RealmID: "14000000-0000-4000-8000-000000000002",
		ProjectID: "14000000-0000-4000-8000-000000000003", ActorID: "14000000-0000-4000-8000-000000000004",
	}
	var user accountdomain.UserID
	require.NoError(t, pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		var err error
		user, err = accountpostgres.CreatePlatformUser(ctx, tx, command)
		return err
	}))
	email, err := accountdomain.NewEmail("initial@example.test")
	require.NoError(t, err)
	bind := accountpostgres.PlatformLifecycle{
		OperationID: "14000000-0000-4000-8000-000000000005", RealmID: command.RealmID, ProjectID: command.ProjectID,
		ActorID: command.ActorID, UserID: user, Action: "initial_email", ExpectedVersion: 1, Email: email,
	}
	apply := func() error {
		return pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
			version, err := accountpostgres.ApplyPlatformLifecycle(ctx, tx, bind)
			if err == nil {
				require.EqualValues(t, 2, version)
			}
			return err
		})
	}
	require.NoError(t, apply())
	require.NoError(t, apply())
	bind.Email, err = accountdomain.NewEmail("different@example.test")
	require.NoError(t, err)
	require.ErrorIs(t, apply(), accountdomain.ErrAccountConflict)
	bind.OperationID = "14000000-0000-4000-8000-000000000006"
	bind.ExpectedVersion = 2
	require.ErrorIs(t, apply(), accountdomain.ErrEmailBindingConflict)
	var unverified bool
	require.NoError(t, db.QueryRow(ctx, `SELECT verified_at IS NULL FROM auth.user_emails WHERE user_id=$1 AND email=$2`, user, email.String()).Scan(&unverified))
	require.True(t, unverified)
}
