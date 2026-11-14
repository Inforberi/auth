package projects_test

import (
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	operators "github.com/Inforberi/financial-intelligence/internal/admin/administrators/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	catalog "github.com/Inforberi/financial-intelligence/internal/admin/projects/repository/postgres"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	authschema "github.com/Inforberi/financial-intelligence/migrations/auth"
)

func roleAdmissionDrill(t *testing.T, physical *pgx.Conn, project *pgxpool.Pool, env func(string) string, reservation domain.PreparationReservation, binding credentials.Binding, codec *credentials.Codec) {
	t.Helper()
	ctx := t.Context()
	admin, err := pgx.Connect(ctx, strings.Replace(env("PROVISIONER_CATALOG_URL"), "auth_platform_preparation_test:catalog-fixture-only@", "auth@", 1))
	require.NoError(t, err)
	projectCfg := physical.Config().Copy()
	projectCfg.Database, _, err = reservation.ResourceNames()
	require.NoError(t, err)
	projectAdmin, err := pgx.ConnectConfig(ctx, projectCfg)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		_, err := projectAdmin.Exec(cleanup, `DELETE FROM auth.platform_role_creations WHERE role_id IN
			(SELECT id FROM auth.roles WHERE key IN ('bridge_drill_editor','bridge_drill_parallel','bridge_drill_outage','bridge_drill_expired','bridge_drill_unknown','bridge_drill_registry') OR key LIKE 'bridge_fault_%' OR key LIKE 'bridge_race_%' OR key LIKE 'bridge_http_%');
			DELETE FROM auth.roles WHERE key IN ('bridge_drill_editor','bridge_drill_parallel','bridge_drill_outage','bridge_drill_expired','bridge_drill_unknown','bridge_drill_registry') OR key LIKE 'bridge_fault_%' OR key LIKE 'bridge_race_%' OR key LIKE 'bridge_http_%'`)
		require.NoError(t, err)
		_, err = admin.Exec(cleanup, `DELETE FROM platform.project_role_outcomes;
			DELETE FROM platform.project_role_admissions; DELETE FROM platform.project_role_intents;
			UPDATE platform.projects SET phase='provisioning',database_name=NULL,credential_ref=NULL,schema_version=0`)
		require.NoError(t, err)
		require.NoError(t, projectAdmin.Close(cleanup))
		require.NoError(t, admin.Close(cleanup))
	})
	var empty bool
	require.NoError(t, admin.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM platform.project_role_intents)`).Scan(&empty))
	require.True(t, empty, "disposable fixture must not replace existing operations")
	actor := operatordomain.Principal{UserID: accountdomain.UserID("d2000000-0000-4000-8000-000000000001"), TokenHash: strings.Repeat("c", 64)}
	// Explicit SQL proof fixture, not a password/TOTP login test.
	_, err = admin.Exec(ctx, `INSERT INTO auth.user_emails(id,user_id,email) VALUES
		('f2000000-0000-4000-8000-000000000001','d2000000-0000-4000-8000-000000000001','bridge@example.test');
		INSERT INTO auth.password_credentials(user_id,email_id,password_hash) VALUES
		('d2000000-0000-4000-8000-000000000001','f2000000-0000-4000-8000-000000000001','sql-fixture-hash');
		INSERT INTO auth.mfa_totp(user_id,secret,last_step) VALUES
		('d2000000-0000-4000-8000-000000000001',decode(repeat('11',64),'hex'),0);
		INSERT INTO platform.operator_permissions(user_id,permission_key) VALUES
		('d2000000-0000-4000-8000-000000000001','platform.project_access.manage')`)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, `INSERT INTO auth.sessions(token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,
		primary_method,primary_verified_at,password_verified_at,mfa_verified_at,mfa_method,user_agent,ip_address)
		VALUES($1,$2,1,statement_timestamp(),statement_timestamp()+interval '1 hour',statement_timestamp()+interval '2 hours',
		'password',statement_timestamp(),statement_timestamp(),statement_timestamp(),'totp','bridge SQL fixture','192.0.2.1')`, actor.TokenHash, actor.UserID)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, `UPDATE platform.projects SET phase='ready',database_name=$1,credential_ref='project:bridge:db:v1',schema_version=$2`, projectCfg.Database, authschema.AuthVersion)
	require.NoError(t, err)
	apiCfg, err := pgxpool.ParseConfig(strings.Replace(env("PROVISIONER_CATALOG_URL"), "auth_platform_preparation_test:catalog-fixture-only@", "auth_platform_api_secrets_test:api-fixture-only@", 1))
	require.NoError(t, err)
	apiCfg.MaxConns, apiCfg.MinConns = 4, 0
	api, err := pgxpool.NewWithConfig(ctx, apiCfg)
	require.NoError(t, err)
	defer api.Close()
	managed := func(pool *pgxpool.Pool) *catalog.Repository {
		authority, err := operators.New(pool, operatordomain.RealmID(binding.RealmID))
		require.NoError(t, err)
		require.NoError(t, authority.CheckRuntime(ctx, false))
		repo, err := catalog.NewManaged(pool, authority, 5*time.Minute, domain.CreationPolicy{
			AuthDomain: "auth.example", PlatformOrigin: "https://console.auth.example", StorageTarget: binding.StorageTarget,
		})
		require.NoError(t, err)
		return repo
	}
	repo := managed(api)
	permissions, err := settings.NewCatalog(nil)
	require.NoError(t, err)
	command := domain.RoleCreation{
		OperationID: "f2000000-0000-4000-8000-000000000011", ProjectID: binding.ProjectID,
		ExpectedVersion: reservation.Version, ExpectedGeneration: reservation.Generation,
		Key: "bridge_drill_editor", Name: "Редактор", Reason: "Bridge drill",
	}
	_, err = repo.AdmitRoleCreation(ctx, actor, command)
	require.ErrorIs(t, err, domain.ErrConflict, "prepared intent is required")
	_, err = repo.PrepareRoleCreation(ctx, actor, command)
	require.NoError(t, err)
	t.Run("trusted project runtime", func(t *testing.T) {
		projectRuntimeDrill(t, admin, repo, actor, command, binding, codec, env, permissions)
	})
	t.Run("concurrent role commands", func(t *testing.T) {
		roleConcurrencyDrill(t, admin, projectAdmin, project, repo, actor, command, permissions)
	})
	grant, err := repo.AdmitRoleCreation(ctx, actor, command)
	require.NoError(t, err)
	copyOfGrant := *grant
	_, err = admin.Exec(ctx, `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE token_hash=$1`, actor.TokenHash)
	require.NoError(t, err)
	_, err = repo.AdmitRoleCreation(ctx, actor, command)
	require.ErrorIs(t, err, operatordomain.ErrForbidden)
	first, err := grant.Execute(ctx, project, permissions, true)
	require.NoError(t, err, "already admitted write may finish after revoke")
	require.True(t, first.CatalogRecorded)
	require.False(t, first.Replayed)
	_, err = grant.Execute(ctx, project, permissions, true)
	require.ErrorIs(t, err, domain.ErrConflict, "same process-local admission is one-use")
	_, err = copyOfGrant.Execute(ctx, project, permissions, true)
	require.ErrorIs(t, err, domain.ErrConflict, "copying an opaque admission must not reset its one-use flag")
	var linked bool
	require.NoError(t, project.QueryRow(ctx, `SELECT admission_id=$2 AND NOT EXISTS(SELECT 1 FROM auth.users)
		FROM auth.platform_role_creations WHERE operation_id=$1`, command.OperationID, grant.ID()).Scan(&linked))
	require.True(t, linked)
	_, err = admin.Exec(ctx, `UPDATE auth.sessions SET revoked_at=NULL WHERE token_hash=$1`, actor.TokenHash)
	require.NoError(t, err)
	retry, err := repo.AdmitRoleCreation(ctx, actor, command)
	require.NoError(t, err)
	replayed, err := retry.Execute(ctx, project, permissions, true)
	require.NoError(t, err)
	require.True(t, replayed.Replayed)
	require.True(t, replayed.CatalogRecorded)
	require.Equal(t, first.Role.ID, replayed.Role.ID)

	t.Run("parallel admissions execute once", func(t *testing.T) {
		c := command
		c.OperationID, c.Key = "f2000000-0000-4000-8000-000000000012", "bridge_drill_parallel"
		_, err := repo.PrepareRoleCreation(ctx, actor, c)
		require.NoError(t, err)
		var wg sync.WaitGroup
		results := make(chan domain.RoleCreationResult, 4)
		failures := make(chan error, 4)
		for range 4 {
			wg.Go(func() {
				a, err := repo.AdmitRoleCreation(ctx, actor, c)
				if err != nil {
					failures <- err
					return
				}
				r, err := a.Execute(ctx, project, permissions, true)
				failures <- err
				results <- r
			})
		}
		wg.Wait()
		close(results)
		close(failures)
		for err := range failures {
			require.NoError(t, err)
		}
		created := 0
		for r := range results {
			if !r.Replayed {
				created++
			}
			require.True(t, r.CatalogRecorded)
		}
		require.Equal(t, 1, created)
	})
	t.Run("catalog lost after admission", func(t *testing.T) {
		c := command
		c.OperationID, c.Key = "f2000000-0000-4000-8000-000000000013", "bridge_drill_outage"
		_, err := repo.PrepareRoleCreation(ctx, actor, c)
		require.NoError(t, err)
		faultPool, err := pgxpool.NewWithConfig(ctx, apiCfg.Copy())
		require.NoError(t, err)
		faultRepo := managed(faultPool)
		admitted, err := faultRepo.AdmitRoleCreation(ctx, actor, c)
		require.NoError(t, err)
		faultPool.Close()
		_, err = faultRepo.AdmitRoleCreation(ctx, actor, c)
		require.Error(t, err)
		committed, err := admitted.Execute(ctx, project, permissions, true)
		require.NoError(t, err)
		require.False(t, committed.CatalogRecorded)
		fresh, err := repo.AdmitRoleCreation(ctx, actor, c)
		require.NoError(t, err)
		recovered, err := fresh.Execute(ctx, project, permissions, true)
		require.NoError(t, err)
		require.True(t, recovered.CatalogRecorded)
		require.True(t, recovered.Replayed)
		require.Equal(t, committed.Role.ID, recovered.Role.ID)
	})
	t.Run("expired admission", func(t *testing.T) {
		c := command
		c.OperationID, c.Key = "f2000000-0000-4000-8000-000000000014", "bridge_drill_expired"
		_, err := repo.PrepareRoleCreation(ctx, actor, c)
		require.NoError(t, err)
		a, err := repo.AdmitRoleCreation(ctx, actor, c)
		require.NoError(t, err)
		timer := time.NewTimer(3100 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		_, err = a.Execute(ctx, project, permissions, true)
		require.ErrorIs(t, err, domain.ErrAdmissionExpired)
		require.NoError(t, project.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM auth.roles WHERE key=$1)`, c.Key).Scan(&empty))
		require.True(t, empty)
	})
	t.Run("commit acknowledgement lost", func(t *testing.T) {
		c := command
		c.OperationID, c.Key = "f2000000-0000-4000-8000-000000000015", "bridge_drill_unknown"
		_, err := repo.PrepareRoleCreation(ctx, actor, c)
		require.NoError(t, err)
		a, err := repo.AdmitRoleCreation(ctx, actor, c)
		require.NoError(t, err)
		_, err = a.Execute(ctx, lostRoleCommitDatabase{project}, permissions, true)
		require.ErrorIs(t, err, domain.ErrOperationOutcomeUnknown)
		var committed bool
		require.NoError(t, project.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.platform_role_creations WHERE operation_id=$1)`, c.OperationID).Scan(&committed))
		require.True(t, committed, "real project COMMIT happened before injected reply loss")
		fresh, err := repo.AdmitRoleCreation(ctx, actor, c)
		require.NoError(t, err)
		recovered, err := fresh.Execute(ctx, project, permissions, true)
		require.NoError(t, err)
		require.True(t, recovered.Replayed)
		require.True(t, recovered.CatalogRecorded)
	})
}

// Fault adapter changes only the COMMIT acknowledgement, after a real SQL commit.
// It does not pretend to be a network/proxy/fleet test.
type lostRoleCommitDatabase struct{ *pgxpool.Pool }

func (db lostRoleCommitDatabase) BeginTx(ctx context.Context, options pgx.TxOptions) (pgx.Tx, error) {
	tx, err := db.Pool.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return lostRoleCommitTransaction{tx}, nil
}

type lostRoleCommitTransaction struct{ pgx.Tx }

func (tx lostRoleCommitTransaction) Commit(ctx context.Context) error {
	if err := tx.Tx.Commit(ctx); err != nil {
		return err
	}
	return io.ErrUnexpectedEOF
}
