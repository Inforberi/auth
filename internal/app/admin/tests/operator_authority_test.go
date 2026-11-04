package admin_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	operatorpostgres "github.com/Inforberi/financial-intelligence/internal/admin/administrators/repository/postgres"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectpostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/repository/postgres"
)

func operatorMutationLocksDrill(t *testing.T, admin, runtime *pgxpool.Pool, authority *operatorpostgres.Repository, actor operatordomain.Principal) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	tx, err := runtime.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := authority.AuthorizeMutation(ctx, tx, actor, operatordomain.ProjectsManage, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	for name, query := range map[string]string{
		"permission": `DELETE FROM platform.operator_permissions WHERE user_id=$1 AND permission_key='platform.projects.manage'`,
		"user":       `UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`,
		"session":    `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE user_id=$1`,
		"password":   `DELETE FROM auth.password_credentials WHERE user_id=$1`,
		"MFA":        `DELETE FROM auth.mfa_totp WHERE user_id=$1`,
	} {
		bounded, stop := context.WithTimeout(ctx, 100*time.Millisecond)
		_, err := admin.Exec(bounded, query, actor.UserID)
		stop()
		if err == nil || !errors.Is(bounded.Err(), context.DeadlineExceeded) {
			t.Fatal("revocation escaped authority locks", name)
		}
	}
	bounded, stop := context.WithTimeout(ctx, 100*time.Millisecond)
	_, err = admin.Exec(bounded, `SELECT pg_advisory_xact_lock(734013981)`)
	stop()
	if err == nil || !errors.Is(bounded.Err(), context.DeadlineExceeded) {
		t.Fatal("role mutation escaped access snapshot lock")
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	manager, err := projectpostgres.NewManaged(runtime, authority, 5*time.Minute, projectdomain.CreationPolicy{AuthDomain: "auth.example", StorageTarget: "primary", PlatformOrigin: "https://console.auth.example"})
	if err != nil {
		t.Fatal(err)
	}
	command := projectdomain.Transition{
		ProjectID: "11111111-1111-4111-8111-111111111111", OperationID: "66666666-6666-4666-8666-666666666666",
		ExpectedVersion: 3, ExpectedGeneration: 3, Action: projectdomain.Suspend, Reason: "fixture-wait",
	}
	// Hold only one project: another project must remain independently writable.
	blocker, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback(context.Background()) }()
	if _, err := blocker.Exec(ctx, `SELECT id FROM platform.projects WHERE id=$1 FOR UPDATE`, command.ProjectID); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := manager.ApplyTransition(ctx, actor, command); done <- err }()
	waitForOperatorProjectLock(t, admin)
	other := command
	other.ProjectID = "22222222-2222-4222-8222-222222222222"
	other.ExpectedVersion, other.ExpectedGeneration = 2, 2
	if _, err := manager.ApplyTransition(ctx, actor, other); err != nil {
		t.Fatal("independent projects serialized", err)
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `DELETE FROM platform.operator_permissions WHERE user_id=$1 AND permission_key='platform.projects.manage'`, actor.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ApplyTransition(ctx, actor, command); !errors.Is(err, operatordomain.ErrForbidden) {
		t.Fatal("replay bypassed revoked authority", err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO platform.operator_permissions VALUES($1,'platform.projects.manage')`, actor.UserID); err != nil {
		t.Fatal(err)
	}
	operatorMutationExpiryDrill(t, admin, manager, actor)
}

func waitForOperatorProjectLock(t *testing.T, admin *pgxpool.Pool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	for {
		var waiting bool
		err := admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()
			AND wait_event_type='Lock' AND query LIKE '%FROM platform.projects WHERE id=$1 FOR UPDATE%')`).Scan(&waiting)
		if err != nil {
			t.Fatal("mutation did not reach project lock", err)
		}
		if waiting {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("project lock wait timeout")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func operatorMutationExpiryDrill(t *testing.T, admin *pgxpool.Pool, manager *projectpostgres.Repository, actor operatordomain.Principal) {
	t.Helper()
	ctx := t.Context()
	if _, err := admin.Exec(ctx, `UPDATE auth.sessions SET mfa_verified_at=clock_timestamp()-interval '298.5 seconds' WHERE token_hash=$1`, actor.TokenHash); err != nil {
		t.Fatal(err)
	}
	blocker, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback(context.Background()) }()
	command := projectdomain.Transition{ProjectID: "11111111-1111-4111-8111-111111111111", OperationID: "77777777-7777-4777-8777-777777777777", ExpectedVersion: 4, ExpectedGeneration: 4, Action: projectdomain.Resume, Reason: "fixture-expiry"}
	if _, err := blocker.Exec(ctx, `SELECT id FROM platform.projects WHERE id=$1 FOR UPDATE`, command.ProjectID); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := manager.ApplyTransition(ctx, actor, command); done <- err }()
	waitForOperatorProjectLock(t, admin)
	if _, err := admin.Exec(ctx, `SELECT pg_sleep(1.7)`); err != nil {
		t.Fatal(err)
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, operatordomain.ErrFreshAuthRequired) {
		t.Fatal("wait extended proof validity", err)
	}
	var version int64
	if err := admin.QueryRow(ctx, `SELECT version FROM platform.projects WHERE id=$1`, command.ProjectID).Scan(&version); err != nil || version != 4 {
		t.Fatal("expired proof committed state", version, err)
	}
	if _, err := admin.Exec(ctx, `UPDATE auth.sessions SET mfa_verified_at=clock_timestamp() WHERE token_hash=$1`, actor.TokenHash); err != nil {
		t.Fatal(err)
	}
}
