package platform_test

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	operators "github.com/Inforberi/financial-intelligence/internal/platform/operator/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	catalog "github.com/Inforberi/financial-intelligence/internal/platform/project/repository/postgres"
)

func roleCreationIntent(t *testing.T, admin *pgxpool.Pool, ctx context.Context, actor operatordomain.Principal) {
	t.Helper()
	_, err := admin.Exec(ctx, `CREATE ROLE auth_role_intent_test LOGIN PASSWORD 'intent-fixture-only'`)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		_, err := admin.Exec(cleanup, `DROP OWNED BY auth_role_intent_test; DROP ROLE auth_role_intent_test`)
		require.NoError(t, err)
	})
	grants, err := os.ReadFile("../../deploy/platform-runtime-grants.sql")
	require.NoError(t, err)
	_, err = admin.Exec(ctx, strings.NewReplacer("auth_platform_runtime", "auth_role_intent_test",
		"DATABASE auth_platform ", "DATABASE auth_platform_test ").Replace(string(grants)))
	require.NoError(t, err)
	cfg := admin.Config().Copy()
	cfg.ConnConfig.User, cfg.ConnConfig.Password = "auth_role_intent_test", "intent-fixture-only"
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(db.Close)
	var realm operatordomain.RealmID
	require.NoError(t, admin.QueryRow(ctx, `SELECT id::text FROM platform.operator_realm`).Scan(&realm))
	authority, err := operators.New(db, realm)
	require.NoError(t, err)
	require.NoError(t, authority.CheckRuntime(ctx, false))
	repo, err := catalog.NewManaged(db, authority, 5*time.Minute, domain.CreationPolicy{
		AuthDomain: "auth.example", StorageTarget: "primary", PlatformOrigin: "https://console.auth.example",
	})
	require.NoError(t, err)
	_, err = admin.Exec(ctx, `INSERT INTO platform.projects(id,slug,name,origin,storage_target,phase,database_name,credential_ref,schema_version)
		VALUES($1::uuid,'intent','Intent','https://intent.auth.example','primary','ready',
		'authp_'||replace($1::uuid::text,'-',''),'project:intent:db:v1',1)`, firstID)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, `INSERT INTO platform.project_preparations(project_id,storage_target,operation_id,version,generation,secrets_created)
		VALUES($1,'primary',gen_random_uuid(),1,1,true)`, firstID)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, `INSERT INTO platform.project_secrets(project_id,reservation_id,storage_target,database_oid,owner_oid,runtime_oid,schema_version,format_version,key_id,ciphertext)
		SELECT project_id,reservation_id,storage_target,100,101,102,1,1,'test',decode(repeat('00',128),'hex') FROM platform.project_preparations WHERE project_id=$1`, firstID)
	require.NoError(t, err)
	command := domain.RoleCreation{
		OperationID: "1c82c477-3a57-4823-8c49-a476550d8a23", ProjectID: firstID,
		ExpectedVersion: 1, ExpectedGeneration: 1, Key: "editor", Name: "Редактор", Reason: "Создание роли",
		Permissions: []accessdomain.PermissionKey{"users.read", "roles.read"},
	}
	first, err := repo.PrepareRoleCreation(ctx, actor, command)
	require.NoError(t, err)
	require.False(t, first.Replayed)
	var xmin string
	require.NoError(t, admin.QueryRow(ctx, `SELECT xmin::text FROM platform.project_role_intents`).Scan(&xmin))
	command.Permissions = []accessdomain.PermissionKey{"roles.read", "users.read"}
	replay, err := repo.PrepareRoleCreation(ctx, actor, command)
	require.NoError(t, err)
	require.True(t, replay.Replayed)
	require.Equal(t, first.CreatedAt, replay.CreatedAt)
	var unchanged bool
	require.NoError(t, admin.QueryRow(ctx, `SELECT xmin::text=$1 FROM platform.project_role_intents`, xmin).Scan(&unchanged))
	require.True(t, unchanged)
	changed := command
	changed.Name = "Другая роль"
	_, err = repo.PrepareRoleCreation(ctx, actor, changed)
	require.ErrorIs(t, err, domain.ErrConflict)

	t.Run("concurrent replay", func(t *testing.T) {
		concurrent := command
		concurrent.OperationID = "1c82c477-3a57-4823-8c49-a476550d8a24"
		var wg sync.WaitGroup
		results := make(chan error, 6)
		for range 6 {
			wg.Go(func() { _, err := repo.PrepareRoleCreation(ctx, actor, concurrent); results <- err })
		}
		wg.Wait()
		close(results)
		for err := range results {
			require.NoError(t, err)
		}
		var count int
		require.NoError(t, admin.QueryRow(ctx, `SELECT count(*) FROM platform.project_role_intents WHERE operation_id=$1`, concurrent.OperationID).Scan(&count))
		require.Equal(t, 1, count)
	})
	roleIntentRefusals(t, admin, ctx, repo, actor, command)
	t.Run("access permission does not require project management", func(t *testing.T) {
		_, err := admin.Exec(ctx, `DELETE FROM platform.operator_permissions WHERE permission_key='platform.projects.manage'`)
		require.NoError(t, err)
		_, prepared := repo.PrepareRoleCreation(ctx, actor, command)
		_, err = admin.Exec(ctx, `INSERT INTO platform.operator_permissions SELECT first_operator_id,'platform.projects.manage' FROM platform.operator_realm`)
		require.NoError(t, err)
		require.NoError(t, prepared)
	})
	t.Run("authority is held during project wait", func(t *testing.T) {
		tx, err := admin.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(ctx) }()
		_, err = tx.Exec(ctx, `SELECT 1 FROM platform.projects FOR UPDATE`)
		require.NoError(t, err)
		result := make(chan error, 1)
		go func() { _, err := repo.PrepareRoleCreation(ctx, actor, command); result <- err }()
		wait, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			var blocked bool
			require.NoError(t, admin.QueryRow(wait, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity
				WHERE usename='auth_role_intent_test' AND wait_event_type='Lock')`).Scan(&blocked))
			if blocked {
				break
			}
			select {
			case <-ticker.C:
			case <-wait.Done():
				t.Fatal("intent did not reach project lock")
			}
		}
		bounded, stop := context.WithTimeout(ctx, 100*time.Millisecond)
		_, revoke := admin.Exec(bounded, `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE token_hash=$1`, actor.TokenHash)
		stop()
		require.ErrorIs(t, revoke, context.DeadlineExceeded)
		require.NoError(t, tx.Rollback(ctx))
		require.NoError(t, <-result)
	})
	t.Run("bounded project lock wait", func(t *testing.T) {
		tx, err := admin.Begin(ctx)
		require.NoError(t, err)
		_, err = tx.Exec(ctx, `SELECT 1 FROM platform.projects FOR UPDATE`)
		require.NoError(t, err)
		bounded, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()
		_, rejected := repo.PrepareRoleCreation(bounded, actor, command)
		require.NoError(t, tx.Rollback(ctx))
		require.ErrorIs(t, rejected, context.DeadlineExceeded)
	})

	for _, grant := range []string{"UPDATE(request)", "INSERT(created_at)", "DELETE", "TRUNCATE"} {
		_, err = admin.Exec(ctx, "GRANT "+grant+" ON platform.project_role_intents TO auth_role_intent_test")
		require.NoError(t, err)
		require.Error(t, authority.CheckRuntime(ctx, false))
		_, err = admin.Exec(ctx, "REVOKE "+grant+" ON platform.project_role_intents FROM auth_role_intent_test")
		require.NoError(t, err)
	}
	require.NoError(t, authority.CheckRuntime(ctx, false))
}

func roleIntentRefusals(t *testing.T, admin *pgxpool.Pool, ctx context.Context, repo *catalog.Repository, actor operatordomain.Principal, command domain.RoleCreation) {
	t.Helper()
	for _, test := range []struct{ name, change, restore string }{
		{"suspended", `UPDATE platform.projects SET desired_state='suspended'`, `UPDATE platform.projects SET desired_state='enabled'`},
		{"not ready", `UPDATE platform.projects SET phase='pending'`, `UPDATE platform.projects SET phase='ready'`},
		{"version", `UPDATE platform.projects SET version=2`, `UPDATE platform.projects SET version=1`},
		{"generation", `UPDATE platform.projects SET generation=2`, `UPDATE platform.projects SET generation=1`},
		{"wrong database", `UPDATE platform.projects SET database_name='auth_wrong'`, `UPDATE platform.projects SET database_name='authp_'||replace(id::text,'-','')`},
		{"binding", `UPDATE platform.project_secrets SET runtime_oid=103`, `UPDATE platform.project_secrets SET runtime_oid=102`},
		{"no secret metadata", `UPDATE platform.project_preparations SET secrets_created=false`, `UPDATE platform.project_preparations SET secrets_created=true`},
		{"revoked session", `UPDATE auth.sessions SET revoked_at=clock_timestamp()`, `UPDATE auth.sessions SET revoked_at=NULL`},
		{"blocked owner", `UPDATE auth.users SET status='blocked'`, `UPDATE auth.users SET status='active'`},
		{"stale password", `UPDATE auth.sessions SET password_verified_at=clock_timestamp()-interval '10 minutes'`, `UPDATE auth.sessions SET password_verified_at=created_at`},
		{
			"stale MFA", `UPDATE auth.sessions SET primary_verified_at=created_at-interval '10 minutes',mfa_verified_at=created_at-interval '6 minutes'`,
			`UPDATE auth.sessions SET primary_verified_at=created_at,mfa_verified_at=created_at`,
		},
		{
			"no access permission", `DELETE FROM platform.operator_permissions WHERE permission_key='platform.project_access.manage'`,
			`INSERT INTO platform.operator_permissions SELECT first_operator_id,'platform.project_access.manage' FROM platform.operator_realm`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := admin.Exec(ctx, test.change)
			require.NoError(t, err)
			_, rejected := repo.PrepareRoleCreation(ctx, actor, command)
			_, err = admin.Exec(ctx, test.restore)
			require.NoError(t, err)
			require.Error(t, rejected)
		})
	}
	wrong := command
	wrong.ProjectID = "1c82c477-3a57-4823-8c49-a476550d8a25"
	_, err := repo.PrepareRoleCreation(ctx, actor, wrong)
	require.ErrorIs(t, err, domain.ErrConflict)
	_, err = admin.Exec(ctx, `ALTER TABLE platform.project_role_intents ADD CONSTRAINT reject_fixture CHECK (false) NOT VALID`)
	require.NoError(t, err)
	newCommand := command
	newCommand.OperationID = "1c82c477-3a57-4823-8c49-a476550d8a26"
	_, rejected := repo.PrepareRoleCreation(ctx, actor, newCommand)
	_, err = admin.Exec(ctx, `ALTER TABLE platform.project_role_intents DROP CONSTRAINT reject_fixture`)
	require.NoError(t, err)
	require.ErrorIs(t, rejected, domain.ErrUnavailable)
	var count int
	require.NoError(t, admin.QueryRow(ctx, `SELECT count(*) FROM platform.project_role_intents WHERE operation_id=$1`, newCommand.OperationID).Scan(&count))
	require.Zero(t, count)
}
