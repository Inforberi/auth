package auth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	projectpostgres "github.com/Inforberi/financial-intelligence/internal/platform/project/repository/postgres"
)

func operatorPreparationDrill(t *testing.T, admin, api *pgxpool.Pool, realm string) {
	t.Helper()
	ctx := t.Context()
	const role = "auth_platform_preparation_test"
	var absent bool
	if err := admin.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)`, role).Scan(&absent); err != nil || !absent {
		t.Fatal("preparation fixture role already exists", err)
	}
	if _, err := admin.Exec(ctx, `CREATE ROLE auth_platform_preparation_test LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, `DROP OWNED BY auth_platform_preparation_test; DROP ROLE auth_platform_preparation_test`); err != nil {
			t.Error("disposable preparation role cleanup", err)
		}
	})
	root := os.Getenv("AUTH_OPERATOR_TEST_ROOT")
	if root == "" {
		root = filepath.Join("..", "..", "..")
	}
	source, err := os.ReadFile(filepath.Join(root, "deploy", "platform-preparation-grants.sql"))
	if err != nil {
		t.Fatal(err)
	}
	grants := strings.NewReplacer("auth_platform_preparation", role, "DATABASE auth_platform ", "DATABASE auth_platform_test ").Replace(string(source))
	if _, err := admin.Exec(ctx, grants); err != nil {
		t.Fatal(err)
	}
	pc := admin.Config().Copy()
	pc.ConnConfig.User = role
	pc.MaxConns = 5
	db, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	repo, err := projectpostgres.NewPreparation(db, domain.ID(realm), "primary")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.CheckRuntime(ctx); err != nil {
		t.Fatal("restricted preparation rejected", err)
	}
	for _, pool := range []*pgxpool.Pool{admin, api} {
		wrong, err := projectpostgres.NewPreparation(pool, domain.ID(realm), "primary")
		if err != nil {
			t.Fatal(err)
		}
		if err := wrong.CheckRuntime(ctx); err == nil {
			t.Fatal("owner/API accepted as preparation credential")
		}
	}
	for _, privilege := range []string{"UPDATE(initialized_at) ON platform.operator_realm", "UPDATE(reservation_id) ON platform.project_preparations", "USAGE ON SCHEMA auth"} {
		if _, err := admin.Exec(ctx, "GRANT "+privilege+" TO "+role); err != nil {
			t.Fatal(err)
		}
		unsafe := repo.CheckRuntime(ctx)
		if _, err := admin.Exec(ctx, "REVOKE "+privilege+" FROM "+role); err != nil {
			t.Fatal(err)
		}
		if unsafe == nil {
			t.Fatal("excess preparation privileges accepted", privilege)
		}
	}
	const project = domain.ID("90000000-0000-4000-8000-000000000001")
	const other = domain.ID("90000000-0000-4000-8000-000000000002")
	const rollback = domain.ID("90000000-0000-4000-8000-000000000003")
	for i, id := range []domain.ID{project, other, rollback} {
		slug := []string{"prepare-one", "prepare-two", "prepare-rollback"}[i]
		if _, err := admin.Exec(ctx, `INSERT INTO platform.projects(id,slug,name,origin,storage_target) VALUES($1,$2,'Preparation fixture',$3,'primary')`, id, slug, "https://"+slug+".auth.example"); err != nil {
			t.Fatal(err)
		}
	}
	input := domain.PreparationRequest{ProjectID: project, OperationID: "91000000-0000-4000-8000-000000000001", ExpectedVersion: 1, ExpectedGeneration: 1}
	wrongTarget, err := projectpostgres.NewPreparation(db, domain.ID(realm), "secondary")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongTarget.Reserve(ctx, input); !errors.Is(err, domain.ErrConflict) {
		t.Fatal("foreign target accepted", err)
	}
	first, err := repo.Reserve(ctx, input)
	if err != nil || first.Version != 2 || first.Generation != 2 || first.StorageTarget != "primary" {
		t.Fatal("reservation failed", err)
	}
	var before, after string
	if err := admin.QueryRow(ctx, `SELECT xmin::text FROM platform.project_preparations WHERE project_id=$1`, project).Scan(&before); err != nil {
		t.Fatal(err)
	}
	results := make(chan domain.PreparationReservation, 4)
	failures := make(chan error, 4)
	for range 4 {
		go func() { result, err := repo.Reserve(ctx, input); results <- result; failures <- err }()
	}
	for range 4 {
		result, err := <-results, <-failures
		if err != nil || result.ReservationID != first.ReservationID || result.OperationID != first.OperationID {
			t.Fatal("parallel replay changed ownership identity", err)
		}
	}
	if err := admin.QueryRow(ctx, `SELECT xmin::text FROM platform.project_preparations WHERE project_id=$1`, project).Scan(&after); err != nil || before != after {
		t.Fatal("reservation replay performed an UPDATE", err)
	}
	if _, _, err := first.ResourceNames(); err != nil {
		t.Fatal(err)
	}
	operatorPreparationRollback(t, admin, repo, rollback)
	blocker, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback(context.Background()) }()
	if _, err := blocker.Exec(ctx, `SELECT id FROM platform.projects WHERE id=$1 FOR UPDATE`, project); err != nil {
		t.Fatal(err)
	}
	bounded, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	_, err = repo.Reserve(bounded, input)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("unbounded preparation lock wait", err)
	}
	second := input
	second.ProjectID = other
	second.OperationID = "91000000-0000-4000-8000-000000000002"
	if result, err := repo.Reserve(ctx, second); err != nil || result.ReservationID == first.ReservationID {
		t.Fatal("independent preparation serialized or shared names", err)
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	operatorPreparationEpoch(t, admin, repo, input, first)
}

func operatorPreparationRollback(t *testing.T, admin *pgxpool.Pool, repo *projectpostgres.PreparationRepository, id domain.ID) {
	t.Helper()
	ctx := t.Context()
	if _, err := admin.Exec(ctx, `ALTER TABLE platform.project_preparations ADD CONSTRAINT fixture_reservation_failure CHECK(project_id<>'90000000-0000-4000-8000-000000000003') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	_, operationErr := repo.Reserve(ctx, domain.PreparationRequest{ProjectID: id, OperationID: "91000000-0000-4000-8000-000000000003", ExpectedVersion: 1, ExpectedGeneration: 1})
	if _, err := admin.Exec(ctx, `ALTER TABLE platform.project_preparations DROP CONSTRAINT fixture_reservation_failure`); err != nil {
		t.Fatal(err)
	}
	var clean bool
	if err := admin.QueryRow(ctx, `SELECT phase='pending' AND version=1 AND generation=1
		AND NOT EXISTS(SELECT 1 FROM platform.project_events WHERE project_id=$1)
		AND NOT EXISTS(SELECT 1 FROM platform.project_preparations WHERE project_id=$1)
		FROM platform.projects WHERE id=$1`, id).Scan(&clean); err != nil || !clean || !errors.Is(operationErr, domain.ErrUnavailable) {
		t.Fatal("reservation error committed partial begin/audit", err, operationErr)
	}
}

func operatorPreparationEpoch(t *testing.T, admin *pgxpool.Pool, repo *projectpostgres.PreparationRepository, input domain.PreparationRequest, first domain.PreparationReservation) {
	t.Helper()
	ctx := t.Context()
	transition := func(action domain.Action, version int64, op domain.ID) {
		t.Helper()
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			defer cancel()
			_ = tx.Rollback(cleanup)
		}()
		kind := domain.OperatorActor
		if action == domain.FailPreparation {
			kind = domain.ProvisionerActor
		}
		_, err = projectpostgres.Transition(ctx, tx, domain.Transition{ProjectID: input.ProjectID, OperationID: op, ExpectedVersion: version, ExpectedGeneration: version, ActorKind: kind, ActorID: input.ProjectID, Action: action, Reason: "fixture-epoch"})
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	transition(domain.Suspend, 2, "92000000-0000-4000-8000-000000000001")
	if _, err := repo.Reserve(ctx, input); !errors.Is(err, domain.ErrConflict) {
		t.Fatal("historical receipt bypassed epoch", err)
	}
	transition(domain.FailPreparation, 3, "92000000-0000-4000-8000-000000000002")
	transition(domain.Resume, 4, "92000000-0000-4000-8000-000000000003")
	transition(domain.RetryPreparation, 5, "92000000-0000-4000-8000-000000000004")
	input.OperationID = "91000000-0000-4000-8000-000000000004"
	input.ExpectedVersion, input.ExpectedGeneration = 6, 6
	again, err := repo.Reserve(ctx, input)
	if err != nil || again.Version != 7 || again.ReservationID != first.ReservationID || !again.CreatedAt.Equal(first.CreatedAt) {
		t.Fatal("explicit retry changed resource reservation", err)
	}
	if _, err := admin.Exec(ctx, `DELETE FROM platform.project_preparations WHERE project_id=$1`, input.ProjectID); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Reserve(ctx, input); !errors.Is(err, domain.ErrConflict) {
		t.Fatal("lost ownership reservation silently replaced", err)
	}
	transition(domain.FailPreparation, 7, "92000000-0000-4000-8000-000000000005")
	transition(domain.RetryPreparation, 8, "92000000-0000-4000-8000-000000000006")
	input.OperationID = "91000000-0000-4000-8000-000000000005"
	input.ExpectedVersion, input.ExpectedGeneration = 9, 9
	if _, err := repo.Reserve(ctx, input); !errors.Is(err, domain.ErrConflict) {
		t.Fatal("new retry regenerated lost storage ownership", err)
	}
}
