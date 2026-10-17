package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
)

func checkTemporaryPasswords(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("flow-no-bypass-no-email-verification", func(t *testing.T) {
		f := newTemporaryFixture(t, db, ctx, "flow")
		created := f.create(t, ctx)
		assertTemporaryState(t, db, ctx, created.UserID, true)
		replay, err := f.service.Provision(ctx, f.input)
		if err != nil || !replay.Reused || replay.Password != "" || replay.UserID != created.UserID {
			t.Fatal("secret replay", replay, err)
		}
		changed := f.input
		changed.Email = "different-temporary@example.com"
		if _, err := f.service.Provision(ctx, changed); !errors.Is(err, accountdomain.ErrProvisionConflict) {
			t.Fatal("command mismatch", err)
		}
		if _, err := New(db).FindByEmail(ctx, f.input.Email); !errors.Is(err, passworddomain.ErrUserNotFound) {
			t.Fatal("ordinary login bypass", err)
		}
		sessions := sessionpostgres.New(db)
		params := sessionservice.CreateSessionParams{UserID: created.UserID, AuthVersion: 1}
		if _, err := sessions.CreateSession(ctx, params); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
			t.Fatal("session issuance bypass", err)
		}
		ledgerToken := temporaryTokenDigest("pending-session:" + string(created.UserID))
		if _, err := db.Exec(ctx, `INSERT INTO auth.sessions(token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,user_agent,ip_address)
			VALUES($1,$2,1,clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours','','127.0.0.1')`, ledgerToken, created.UserID); err != nil {
			t.Fatal(err)
		}
		if _, err := sessions.FindSession(ctx, ledgerToken); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
			t.Fatal("pending session validation bypass", err)
		}
		if _, err := sessions.RefreshSession(ctx, ledgerToken, &sessiondomain.Session{UserID: created.UserID, ExpiresAt: time.Now().Add(time.Hour)}, time.Now()); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
			t.Fatal("pending refresh bypass", err)
		}
		if _, err := f.accounts.ChangeStatus(ctx, accountdomain.StatusChange{UserID: created.UserID, ActorID: f.input.Actor.UserID, Status: accountdomain.StatusActive, ExpectedVersion: 1}); !errors.Is(err, accountdomain.ErrAccountConflict) {
			t.Fatal("status bypass", err)
		}
		if err := New(db).IssueReset(ctx, f.input.Email, passworddomain.ResetChallenge{Digest: temporaryTokenDigest("reset"), Payload: []byte("test-mail"), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		var resetCount int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.password_resets WHERE user_id=$1`, created.UserID).Scan(&resetCount); err != nil || resetCount != 0 {
			t.Fatal("ordinary recovery bypass", resetCount, err)
		}
		first := f.login(t, ctx, created.Password)
		setup := f.login(t, ctx, created.Password)
		if _, err := f.repo.CheckTemporarySetup(ctx, temporaryTokenDigest(first.Token)); !errors.Is(err, passworddomain.ErrInvalidTemporaryPassword) {
			t.Fatal("previous setup still valid", err)
		}
		if _, err := sessions.FindSession(ctx, temporaryTokenDigest(setup.Token)); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
			t.Fatal("setup token accepted as session", err)
		}
		if err := f.accounts.CheckInvitation(ctx, temporaryTokenDigest(setup.Token)); !errors.Is(err, accountdomain.ErrInvalidInvitation) {
			t.Fatal("setup accepted as invitation", err)
		}
		command := accountservice.InvitationReissueCommand{Input: accountservice.InvitationReissueInput{Actor: f.input.Actor, UserID: created.UserID, IdempotencyKey: temporaryRequestKey(t, db, ctx)}, Email: f.input.Email, Cooldown: time.Second}
		if _, err := f.accounts.ReissueInvitation(ctx, command); !errors.Is(err, accountdomain.ErrInvalidInvitation) {
			t.Fatal("invitation bypassed mandatory password change", err)
		}
		var wg sync.WaitGroup
		errs := make(chan error, 16)
		for range 16 {
			wg.Go(func() {
				errs <- f.service.Complete(ctx, setup.Token, "PermanentExamplePass123", "PermanentExamplePass123", "ip")
			})
		}
		wg.Wait()
		close(errs)
		successes := 0
		for err := range errs {
			if err == nil {
				successes++
			} else if !errors.Is(err, passworddomain.ErrInvalidTemporaryPassword) {
				t.Fatal(err)
			}
		}
		if successes != 1 {
			t.Fatal("setup consumed more than once", successes)
		}
		assertTemporaryState(t, db, ctx, created.UserID, false)
		if _, err := f.service.Login(ctx, f.input.Email, created.Password, "ip"); !errors.Is(err, passworddomain.ErrInvalidTemporaryPassword) {
			t.Fatal("temporary password remained usable", err)
		}
		credential, err := New(db).FindByEmail(ctx, f.input.Email)
		if err != nil || (temporaryFixtureHash{}).Compare(ctx, "PermanentExamplePass123", credential.PasswordHash) != nil {
			t.Fatal("permanent password missing", err)
		}
		if err := f.accounts.RequireVerified(ctx, created.UserID); !errors.Is(err, accountdomain.ErrEmailUnverified) {
			t.Fatal("temporary password verified email", err)
		}
	})
	t.Run("reissue-revokes-secret-and-authority", func(t *testing.T) {
		f := newTemporaryFixture(t, db, ctx, "reissue")
		created := f.create(t, ctx)
		setup := f.login(t, ctx, created.Password)
		input := passwordservice.TemporaryReissueInput{Actor: f.input.Actor, UserID: created.UserID, IdempotencyKey: temporaryRequestKey(t, db, ctx)}
		if _, err := f.service.Reissue(ctx, input); !errors.Is(err, passworddomain.ErrTemporaryPasswordCooldown) {
			t.Fatal("initial cooldown ignored", err)
		}
		allowTemporaryReissue(t, db, ctx, created.UserID)
		expected, err := f.repo.FindTemporary(ctx, f.input.Email)
		if err != nil {
			t.Fatal(err)
		}
		reissued, err := f.service.Reissue(ctx, input)
		if err != nil || reissued.Password == "" || reissued.Password == created.Password || reissued.UserID != created.UserID {
			t.Fatal("invalid reissue", reissued, err)
		}
		if _, err := f.repo.BeginTemporary(ctx, *expected, temporaryTokenDigest("stale"), time.Minute); !errors.Is(err, passworddomain.ErrInvalidTemporaryPassword) {
			t.Fatal("stale hash snapshot accepted", err)
		}
		if _, err := f.service.Login(ctx, f.input.Email, created.Password, "ip"); !errors.Is(err, passworddomain.ErrInvalidTemporaryPassword) {
			t.Fatal("old password accepted", err)
		}
		if err := f.service.Complete(ctx, setup.Token, "PermanentExamplePass123", "PermanentExamplePass123", "ip"); !errors.Is(err, passworddomain.ErrInvalidTemporaryPassword) {
			t.Fatal("old setup accepted", err)
		}
		replay, err := f.service.Reissue(ctx, input)
		if err != nil || !replay.Reused || replay.Password != "" || !replay.ExpiresAt.Equal(reissued.ExpiresAt) {
			t.Fatal("reissue replay", replay, err)
		}
		f.login(t, ctx, reissued.Password)
	})
	checkTemporaryConcurrency(t, db, ctx)
	checkTemporaryFailures(t, db, ctx)
}
