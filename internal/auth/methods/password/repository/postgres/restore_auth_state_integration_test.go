package postgres

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	tokendomain "github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	tokenpostgres "github.com/Inforberi/financial-intelligence/internal/auth/token/repository/postgres"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func TestRestoreAuthStateSchema(t *testing.T) {
	container := os.Getenv("AUTH_RESTORE_TEST_CONTAINER")
	if container == "" {
		t.Skip("explicit disposable restore container not configured")
	}
	if !strings.HasPrefix(container, "auth-j72-") || strings.ContainsAny(container, " \n\r\t/") {
		t.Fatal("restore requires a dedicated auth-j72- container")
	}
	db, ctx := schemaFixtureDSN(t, os.Getenv("AUTH_SCHEMA_TEST_DATABASE_URL"), 2*time.Minute)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	root := filepath.Join("..", "..", "..", "..", "..", "..")
	script, err := os.ReadFile(filepath.Join(root, "deploy", "restore-auth-state.sql"))
	if err != nil {
		t.Fatal(err)
	}
	runSQL := func(user string, sql []byte) error {
		_, err := restoreDocker(ctx, container, sql, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", user, "-d", "auth_schema_test")
		return err
	}
	apply := func() {
		t.Helper()
		if err := runSQL("auth_schema_test", script); err != nil {
			t.Fatal("invalidation failed", err)
		}
	}

	svc, input, keys := nativeIssuanceFixture(t, db, ctx)
	issued, err := svc.IssueNative(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := authjwt.NewVerifier(authjwt.Expectations{Issuer: "https://auth.example", Audience: "orders", Mode: authjwt.Strict}, keys, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	claims, err := verifier.VerifySignature(ctx, issued.Raw, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cookie := jwtActor(t, db, ctx)
	mfa := newMFALoginFixture(t, db, ctx, "restore")
	mfaInput := mfa.start(t, ctx)
	temporary := newTemporaryFixture(t, db, ctx, "restore")
	temporarySecret := temporary.create(t, ctx)
	_ = temporary.login(t, ctx, temporarySecret.Password)
	change := newChangeFixture(t, db, ctx, "restore")
	if err := change.request(ctx); err != nil {
		t.Fatal(err)
	}
	seedRestoreProofs(t, db, ctx, string(input.Proof.UserID), string(mfa.user), string(temporarySecret.UserID))
	stable := restoreStableState(t, db, ctx)
	archive, err := restoreDocker(ctx, container, nil, "pg_dump", "-U", "auth_schema_test", "-d", "auth_schema_test", "-Fc", "--no-owner", "--no-privileges")
	if err != nil || len(archive) == 0 || len(archive) > 16<<20 {
		t.Fatal("synthetic backup failed or exceeded fixture budget", err)
	}

	refresh := tokenservice.RefreshInput{Token: issued.RefreshToken, IP: input.IP}
	if _, err := svc.Refresh(ctx, refresh); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Refresh(ctx, refresh); !errors.Is(err, tokendomain.ErrInvalidRefresh) {
		t.Fatal("replay did not revoke", err)
	}
	if err := sessionpostgres.New(db).RevokeOwnSession(ctx, cookie.Actor.UserID, cookie.Actor.TokenHash, cookie.SessionID); err != nil {
		t.Fatal(err)
	}
	if err := New(db).ConsumeReset(ctx, strings.Repeat("a", 64), "changed-after-backup"); err != nil {
		t.Fatal(err)
	}
	if _, err := mfa.login.Complete(ctx, mfaInput); err != nil {
		t.Fatal(err)
	}
	if _, err := tokenpostgres.New(db).Introspect(ctx, claims, input.Scope); !errors.Is(err, authjwt.ErrInvalidToken) {
		t.Fatal("pre-restore revoke missing", err)
	}
	if _, err := restoreDocker(ctx, container, archive, "pg_restore", "-U", "auth_schema_test", "-d", "auth_schema_test", "--clean", "--if-exists", "--single-transaction", "--exit-on-error", "--no-owner", "--no-privileges"); err != nil {
		t.Fatal("synthetic restore failed", err)
	}
	if _, err := tokenpostgres.New(db).Introspect(ctx, claims, input.Scope); err != nil {
		t.Fatal("fixture did not restore the vulnerable old snapshot", err)
	}
	if _, err := sessionpostgres.New(db).FindSession(ctx, cookie.Actor.TokenHash); err != nil {
		t.Fatal("cookie snapshot not restored", err)
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }() //nolint:gosec // Explicit rollback below releases the synthetic writer lock.
	if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err := runSQL("auth_schema_test", script); err == nil {
		t.Fatal("restore ran behind an active Access writer")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	// The last audit insert fails: every preceding revoke/delete/version change must roll back.
	accessExec(t, db, ctx, `CREATE FUNCTION auth.reject_restore_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic restore audit failure'; END $$;
		CREATE TRIGGER reject_restore_audit BEFORE INSERT ON auth.restore_audit FOR EACH ROW EXECUTE FUNCTION auth.reject_restore_audit()`)
	if err := runSQL("auth_schema_test", script); err == nil {
		t.Fatal("audit failure committed invalidation")
	}
	if restoreStableState(t, db, ctx) != stable {
		t.Fatal("failed operation changed permanent state")
	}
	if _, err := tokenpostgres.New(db).Introspect(ctx, claims, input.Scope); err != nil {
		t.Fatal("failed operation revoked partially", err)
	}
	var resetPresent bool
	if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.password_resets) AND NOT EXISTS(SELECT 1 FROM auth.restore_audit)`).Scan(&resetPresent); err != nil || !resetPresent {
		t.Fatal("failed operation cleared proof or wrote audit", err)
	}
	accessExec(t, db, ctx, `DROP TRIGGER reject_restore_audit ON auth.restore_audit; DROP FUNCTION auth.reject_restore_audit()`)
	checkRestoreRuntime(t, db, ctx, root, runSQL, script)
	apply()
	assertRestoreInvalidated(t, db, ctx, 1)
	if restoreStableState(t, db, ctx) != stable {
		t.Fatal("invalidation changed accounts/roles/permanent factors/provisioning")
	}
	if _, err := sessionpostgres.New(db).FindSession(ctx, cookie.Actor.TokenHash); err == nil {
		t.Fatal("restored cookie still active")
	}
	if _, err := svc.Refresh(ctx, refresh); !errors.Is(err, tokendomain.ErrInvalidRefresh) {
		t.Fatal("restored refresh still active", err)
	}
	if _, err := tokenpostgres.New(db).Introspect(ctx, claims, input.Scope); !errors.Is(err, authjwt.ErrInvalidToken) {
		t.Fatal("restored strict access still active", err)
	}
	if err := New(db).ConsumeReset(ctx, strings.Repeat("a", 64), "new-hash"); !errors.Is(err, passworddomain.ErrInvalidReset) {
		t.Fatal("restored password reset still active", err)
	}
	if _, err := mfa.login.Complete(ctx, mfaInput); !errors.Is(err, mfadomain.ErrInvalidCode) {
		t.Fatal("restored MFA challenge still active", err)
	}
	if _, err := temporary.service.Login(ctx, temporary.input.Email, temporarySecret.Password, "127.0.0.1"); err == nil {
		t.Fatal("restored temporary password still active")
	}
	apply()
	assertRestoreInvalidated(t, db, ctx, 2)
	if restoreStableState(t, db, ctx) != stable {
		t.Fatal("retry changed permanent state")
	}
	// A newly verified primary proof may create a new API family; old verifiers remain revoked.
	if err := db.QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1`, input.Proof.UserID).Scan(&input.Proof.AuthVersion); err != nil {
		t.Fatal(err)
	}
	input.Proof.VerifiedAt = time.Now().UTC()
	if _, err := svc.IssueNative(ctx, input); err != nil {
		t.Fatal("new primary proof could not issue after recovery", err)
	}
}

func restoreDocker(ctx context.Context, container string, input []byte, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "docker", append([]string{"exec", "-i", container}, args...)...)
	command.Stdin = bytes.NewReader(input)
	return command.Output()
}

func checkRestoreRuntime(t *testing.T, db *pgxpool.Pool, ctx context.Context, root string, runSQL func(string, []byte) error, script []byte) {
	t.Helper()
	accessExec(t, db, ctx, `CREATE ROLE auth_restore_runtime LOGIN`)
	t.Cleanup(func() { accessExec(t, db, ctx, `DROP OWNED BY auth_restore_runtime; DROP ROLE auth_restore_runtime`) })
	grants, err := os.ReadFile(filepath.Join(root, "deploy", "runtime-grants.sql"))
	if err != nil {
		t.Fatal(err)
	}
	adapted := strings.ReplaceAll(string(grants), "auth_runtime", "auth_restore_runtime")
	adapted = strings.ReplaceAll(adapted, "ON DATABASE auth TO", "ON DATABASE auth_schema_test TO")
	accessExec(t, db, ctx, adapted)
	if err := runSQL("auth_restore_runtime", script); err == nil {
		t.Fatal("runtime executed owner recovery")
	}
	var permitted bool
	if err := db.QueryRow(ctx, `SELECT has_table_privilege('auth_restore_runtime','auth.restore_audit','INSERT')`).Scan(&permitted); err != nil || permitted {
		t.Fatal("runtime can forge restore audit", err)
	}
}
