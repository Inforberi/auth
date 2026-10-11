package postgres

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	passwordhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
)

func checkRegistrationFailures(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	f := newRegistrationFixture(t, db, ctx)
	const password = "ExamplePass1"
	t.Run("queued verification rollback", func(t *testing.T) {
		const email = "registration-rollback@example.com"
		failure := errors.New("verification unavailable")
		var before, after int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.users`).Scan(&before); err != nil {
			t.Fatal(err)
		}
		broken := NewWithRegistration(db, func(ctx context.Context, tx pgx.Tx, user accountdomain.UserID, emailID accountdomain.AddressID, email string) error {
			if err := f.passwords.registration(ctx, tx, user, emailID, email); err != nil {
				return err
			}
			return failure
		})
		svc := passwordservice.New(broken, f.sessions, temporaryFixtureHash{}, loginTestLimit{})
		assertRegistrationHTTPFailure(t, ctx, svc, email, 500)
		if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.users`).Scan(&after); err != nil || after != before {
			t.Fatal("rollback left user", err)
		}
		if found, err := f.passwords.ExistsByEmail(ctx, email); err != nil || found {
			t.Fatal("rollback reserved email", err)
		}
		if _, err := f.service.Register(ctx, email, password, "test", "127.0.0.1"); err != nil {
			t.Fatal("retry after rollback failed", err)
		}
		assertRegistrationRows(t, db, ctx, email, 1)
	})
	t.Run("account commit reply lost", func(t *testing.T) {
		const email = "registration-account-reply@example.com"
		failure := context.DeadlineExceeded
		svc := passwordservice.New(registrationCommitReplyFailure{f.passwords, failure}, f.sessions, temporaryFixtureHash{}, loginTestLimit{})
		assertRegistrationHTTPFailure(t, ctx, svc, email, 503)
		checkRegistrationRetryAndLogin(t, db, ctx, f, email, password, 0)
	})
	for _, afterCommit := range []bool{false, true} {
		name := "session failed before commit"
		email := "registration-session-failure@example.com"
		sessions := 0
		if afterCommit {
			name, email, sessions = "session commit reply lost", "registration-session-reply@example.com", 1
		}
		t.Run(name, func(t *testing.T) {
			failure := context.DeadlineExceeded
			broken := registrationSessionFailure{f.sessions, afterCommit, failure}
			svc := passwordservice.New(f.passwords, broken, temporaryFixtureHash{}, loginTestLimit{})
			assertRegistrationHTTPFailure(t, ctx, svc, email, 503)
			checkRegistrationRetryAndLogin(t, db, ctx, f, email, password, sessions)
		})
	}
}

func assertRegistrationHTTPFailure(t *testing.T, ctx context.Context, svc *passwordservice.PasswordService, email string, status int) {
	t.Helper()
	r := httptest.NewRequest("POST", "/api/v1/auth/register/email", strings.NewReader(`{"email":"`+email+`","password":"ExamplePass1"}`)).WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	passwordhttp.New(svc, zap.NewNop()).Register(w, r)
	want := "temporarily_unavailable"
	if status == 500 {
		want = "internal_error"
	}
	if w.Code != status || !strings.Contains(w.Body.String(), `"code":"`+want+`"`) || strings.Contains(w.Body.String(), "verification unavailable") || strings.Contains(w.Body.String(), "userID") || len(w.Result().Cookies()) != 0 {
		t.Fatal("registration failure exposed authority/private error", w.Code, w.Body.String(), w.Header())
	}
}

func checkRegistrationRetryAndLogin(t *testing.T, db *pgxpool.Pool, ctx context.Context, f registrationFixture, email, password string, sessions int) {
	t.Helper()
	assertRegistrationRows(t, db, ctx, email, sessions)
	if result, err := f.service.Register(ctx, email, password, "test", "127.0.0.1"); result != nil || !errors.Is(err, passworddomain.ErrEmailAlreadyExists) {
		t.Fatal("retry did not preserve conflict", result, err)
	}
	assertRegistrationRows(t, db, ctx, email, sessions)
	if result, err := f.service.Login(ctx, passwordservice.LoginInput{Email: email, Password: "WrongPass1", IP: "127.0.0.1"}); result != nil || !errors.Is(err, passworddomain.ErrInvalidEmailOrPassword) {
		t.Fatal("retry granted access without password", result, err)
	}
	assertRegistrationRows(t, db, ctx, email, sessions)
	login, err := f.service.Login(ctx, passwordservice.LoginInput{Email: email, Password: password, IP: "127.0.0.1"})
	if err != nil || login == nil || login.Token == "" {
		t.Fatal("created account cannot log in", err)
	}
	assertRegistrationRows(t, db, ctx, email, sessions+1)
}
