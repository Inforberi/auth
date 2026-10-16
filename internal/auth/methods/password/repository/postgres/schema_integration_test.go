package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	migrateFixture(t, db, ctx, "down")
	var present bool
	if err := db.QueryRow(ctx, "SELECT to_regnamespace('auth') IS NOT NULL").Scan(&present); err != nil || present {
		t.Fatal("down did not remove auth schema")
	}
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	repo := New(db)
	t.Run("MFA foundation", func(t *testing.T) { checkMFAFoundation(t, db, ctx) })
	t.Run("MFA login", func(t *testing.T) { checkMFALogin(t, db, ctx) })
	t.Run("MFA management", func(t *testing.T) { checkMFAManagement(t, db, ctx) })
	t.Run("MFA HTTP login", func(t *testing.T) { checkMFAHTTPLogin(t, db, ctx) })
	t.Run("administrator protection", func(t *testing.T) { checkAdministratorProtection(t, db, ctx) })
	t.Run("access roles", func(t *testing.T) { checkAccessRoles(t, db, ctx) })
	t.Run("email OTP", func(t *testing.T) { checkEmailOTP(t, db, ctx) })
	t.Run("email reauthentication", func(t *testing.T) { checkEmailReauthentication(t, db, ctx) })
	t.Run("initial email binding", func(t *testing.T) { checkEmailBinding(t, db, ctx) })
	t.Run("external identities", func(t *testing.T) { checkIdentityResolution(t, db, ctx) })
	t.Run("identity management", func(t *testing.T) { checkIdentityManagement(t, db, ctx) })
	t.Run("Google identity", func(t *testing.T) { checkGoogleIdentity(t, db, ctx) })
	t.Run("password rehash", func(t *testing.T) { checkPasswordRehash(t, db, ctx) })
	t.Run("password recovery", func(t *testing.T) { checkRecovery(t, db, ctx) })
	t.Run("email verification", func(t *testing.T) { checkVerification(t, db, ctx) })
	t.Run("repository", func(t *testing.T) { checkRepository(t, db, ctx, repo) })
	t.Run("constraints", func(t *testing.T) { checkConstraints(t, db, ctx, repo) })
	t.Run("concurrent registration", func(t *testing.T) { checkConcurrentRegistration(t, db, ctx, repo) })
	t.Run("registration service race", func(t *testing.T) { checkRegistrationServiceRace(t, db, ctx) })
	t.Run("registration failures", func(t *testing.T) { checkRegistrationFailures(t, db, ctx) })
	t.Run("session management", func(t *testing.T) { checkSessionManagement(t, db, ctx) })
	t.Run("session rotation", func(t *testing.T) { checkSessionRotation(t, db, ctx) })
	t.Run("fresh authentication", func(t *testing.T) { checkFreshAuthentication(t, db, ctx) })
	t.Run("concurrent refresh", func(t *testing.T) { checkConcurrentRefresh(t, db, ctx) })
	t.Run("session HTTP response ordering", func(t *testing.T) { checkSessionHTTPResponseOrdering(t, db, ctx) })
	t.Run("account status", func(t *testing.T) { checkAccountStatus(t, db, ctx) })
	t.Run("email change", func(t *testing.T) { checkEmailChange(t, db, ctx) })
	t.Run("protected recovery", func(t *testing.T) { checkProtectedRecovery(t, db, ctx) })
	t.Run("protected recovery races", func(t *testing.T) { checkProtectedRecoveryRaces(t, db, ctx) })
	t.Run("protected recovery delivery", func(t *testing.T) { checkProtectedRecoveryDelivery(t, db, ctx) })
	t.Run("account deletion", func(t *testing.T) { checkAccountDeletion(t, db, ctx) })
	t.Run("retention", func(t *testing.T) { checkRetention(t, db, ctx) })
	t.Run("invitations", func(t *testing.T) { checkInvitations(t, db, ctx) })
	t.Run("invitation reissue", func(t *testing.T) { checkInvitationReissue(t, db, ctx) })
	t.Run("temporary password", func(t *testing.T) { checkTemporaryPasswords(t, db, ctx) })
	t.Run("invitation delivery", func(t *testing.T) { checkInvitationDelivery(t, db, ctx) })
	t.Run("provision rollback", func(t *testing.T) { checkProvisionRollback(t, db, ctx) })
}

func expectSQLState(t *testing.T, db *pgxpool.Pool, ctx context.Context, code, sql string, args ...any) {
	t.Helper()
	_, err := db.Exec(ctx, sql, args...)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code {
		t.Fatalf("expected SQLSTATE %s, got %v", code, err)
	}
}
