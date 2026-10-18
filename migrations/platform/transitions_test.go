package platform_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	catalog "github.com/Inforberi/financial-intelligence/internal/platform/project/repository/postgres"
)

func transitionID(n int) domain.ID {
	return domain.ID(fmt.Sprintf("00000000-0000-4000-8000-%012d", n))
}

func transitionCommand(project domain.ID, operation int, version int64, action domain.Action) domain.Transition {
	kind := domain.OperatorActor
	if action == domain.BeginPreparation || action == domain.FailPreparation || action == domain.FinishPreparation {
		kind = domain.ProvisionerActor
	}
	return domain.Transition{
		ProjectID: project, OperationID: transitionID(operation), Action: action, ActorKind: kind,
		ActorID: transitionID(9999), ExpectedVersion: version, ExpectedGeneration: version, Reason: "fixture-incident",
	}
}

func applyTransition(ctx context.Context, db *pgxpool.Pool, command domain.Transition, commit bool) (domain.TransitionReceipt, error) {
	tx, err := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return domain.TransitionReceipt{}, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	result, err := catalog.Transition(ctx, tx, command)
	if err != nil {
		return domain.TransitionReceipt{}, err
	}
	if commit {
		err = tx.Commit(ctx)
	}
	return result, err
}

func TestProjectTransitionsPostgres(t *testing.T) {
	db, ctx := catalogFixture(t)
	repo := catalog.New(db)
	create := func(n int) domain.ID {
		t.Helper()
		id := transitionID(n)
		_, err := db.Exec(ctx, `INSERT INTO platform.projects(id,slug,name,origin,storage_target) VALUES($1,$2,'Fixture',$3,'primary')`, id,
			fmt.Sprintf("transition-%d", n), fmt.Sprintf("https://transition-%d.auth.example", n))
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	t.Run("lifecycle and durable replay", func(t *testing.T) {
		id := create(1)
		for i, action := range []domain.Action{domain.BeginPreparation, domain.FailPreparation, domain.RetryPreparation, domain.BeginPreparation, domain.Suspend} {
			command := transitionCommand(id, i+1, int64(i+1), action)
			r, err := applyTransition(ctx, db, command, true)
			if err != nil || r.Version != int64(i+2) || r.Generation != r.Version || r.Replayed {
				t.Fatal("lifecycle transition", action, r, err)
			}
		}
		if _, err := applyTransition(ctx, db, transitionCommand(id, 6, 5, domain.FinishPreparation), true); !errors.Is(err, domain.ErrConflict) {
			t.Fatal("stale executor completed after suspension", err)
		}
		finish := transitionCommand(id, 6, 6, domain.FinishPreparation)
		if _, err := applyTransition(ctx, db, finish, true); !errors.Is(err, domain.ErrInvalidTransition) {
			t.Fatal("ready without binding accepted", err)
		}
		if _, err := db.Exec(ctx, `UPDATE platform.projects SET database_name='auth_fixture',credential_ref='fixture:db:v1',schema_version=1 WHERE id=$1`, id); err != nil {
			t.Fatal(err)
		}
		if _, err := applyTransition(ctx, db, finish, true); err != nil {
			t.Fatal(err)
		}
		p, err := repo.Read(ctx, id)
		if err != nil || p.Phase != domain.Ready || p.DesiredState != domain.Suspended || p.AdmitsRequests() {
			t.Fatal("in-flight completion undid suspension", err)
		}
		if _, err := repo.Resolve(ctx, p.Origin); !errors.Is(err, domain.ErrNotFound) {
			t.Fatal("suspended ready project resolved", err)
		}
		if _, err := applyTransition(ctx, db, transitionCommand(id, 7, 7, domain.Resume), true); err != nil {
			t.Fatal(err)
		}
		binding, err := repo.Resolve(ctx, p.Origin)
		if err != nil || binding.Project.Generation != 8 || !binding.Project.AdmitsRequests() {
			t.Fatal("resumed project did not resolve", err)
		}
		before, err := repo.Read(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		original := transitionCommand(id, 1, 1, domain.BeginPreparation)
		r, err := applyTransition(ctx, db, original, true)
		if err != nil || !r.Replayed || r.Version != 2 || r.Phase != domain.Provisioning {
			t.Fatal("lost-response replay did not return original receipt", r, err)
		}
		for _, mutate := range []func(*domain.Transition){
			func(c *domain.Transition) { c.Reason = "another incident" },
			func(c *domain.Transition) { c.ActorID = transitionID(8888) },
			func(c *domain.Transition) { c.ExpectedGeneration++ },
		} {
			other := original
			mutate(&other)
			if _, err := applyTransition(ctx, db, other, true); !errors.Is(err, domain.ErrConflict) {
				t.Fatal("operation UUID reused with another payload", err)
			}
		}
		for _, action := range []domain.Action{domain.Resume, domain.BeginPreparation, domain.RetryPreparation} {
			if _, err := applyTransition(ctx, db, transitionCommand(id, 8, 8, action), true); !errors.Is(err, domain.ErrInvalidTransition) {
				t.Fatal("invalid ready transition accepted", action, err)
			}
		}
		wrongGeneration := transitionCommand(id, 8, 8, domain.Suspend)
		wrongGeneration.ExpectedGeneration = 7
		if _, err := applyTransition(ctx, db, wrongGeneration, true); !errors.Is(err, domain.ErrConflict) {
			t.Fatal("foreign runtime generation accepted", err)
		}
		after, err := repo.Read(ctx, id)
		var count int
		if err != nil || before != after {
			t.Fatal("rejected/replayed command changed metadata", err)
		}
		if err := db.QueryRow(ctx, `SELECT count(*) FROM platform.project_events WHERE project_id=$1`, id).Scan(&count); err != nil || count != 7 {
			t.Fatal("unexpected audit count", count, err)
		}
	})
	t.Run("rollback and audit failure", func(t *testing.T) {
		id := create(20)
		command := transitionCommand(id, 20, 1, domain.Suspend)
		before, err := repo.Read(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := applyTransition(ctx, db, command, false); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `ALTER TABLE platform.project_events ADD CONSTRAINT fixture_audit_denied CHECK(action<>'suspend') NOT VALID`); err != nil {
			t.Fatal(err)
		}
		_, transitionErr := applyTransition(ctx, db, command, true)
		if _, err := db.Exec(ctx, `ALTER TABLE platform.project_events DROP CONSTRAINT fixture_audit_denied`); err != nil {
			t.Fatal(err)
		}
		if !errors.Is(transitionErr, domain.ErrUnavailable) || strings.Contains(transitionErr.Error(), "fixture_audit_denied") {
			t.Fatal("audit failure not sanitized", transitionErr)
		}
		after, err := repo.Read(ctx, id)
		var count int
		if err != nil || before != after {
			t.Fatal("failed/rolled-back transition persisted", err)
		}
		if err := db.QueryRow(ctx, `SELECT count(*) FROM platform.project_events WHERE project_id=$1`, id).Scan(&count); err != nil || count != 0 {
			t.Fatal("failed transition left an audit receipt", err)
		}
	})
	t.Run("parallel versions and duplicate operation", func(t *testing.T) {
		for _, duplicate := range []bool{false, true} {
			index := 30
			if duplicate {
				index = 31
			}
			id := create(index)
			type outcome struct {
				result domain.TransitionReceipt
				err    error
			}
			results := make(chan outcome, 2)
			start := make(chan struct{})
			for i := range 2 {
				command := transitionCommand(id, 100+i, 1, domain.Suspend)
				if duplicate {
					command.OperationID = transitionID(100)
				}
				go func() {
					<-start
					r, err := applyTransition(ctx, db, command, true)
					results <- outcome{r, err}
				}()
			}
			close(start)
			successes, conflicts, replays := 0, 0, 0
			for range 2 {
				o := <-results
				switch {
				case o.err == nil:
					successes++
					if o.result.Replayed {
						replays++
					}
				case errors.Is(o.err, domain.ErrConflict):
					conflicts++
				default:
					t.Fatal("parallel transition failed", o.err)
				}
			}
			if (duplicate && (successes != 2 || replays != 1)) || (!duplicate && (successes != 1 || conflicts != 1)) {
				t.Fatal("unexpected concurrent outcomes", duplicate, successes, conflicts, replays)
			}
			var count int
			if err := db.QueryRow(ctx, `SELECT count(*) FROM platform.project_events WHERE project_id=$1`, id).Scan(&count); err != nil || count != 1 {
				t.Fatal("concurrent audit duplicated", err)
			}
		}
	})
	t.Run("bounded row lock and independent projects", func(t *testing.T) {
		id, other := create(40), create(41)
		tx, err := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `SELECT id FROM platform.projects WHERE id=$1 FOR UPDATE`, id); err != nil {
			t.Fatal(err)
		}
		deadline, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel()
		if _, err := applyTransition(deadline, db, transitionCommand(id, 40, 1, domain.Suspend), true); !errors.Is(err, domain.ErrUnavailable) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("blocked transition lost deadline", err)
		}
		if _, err := applyTransition(ctx, db, transitionCommand(other, 41, 1, domain.Suspend), true); err != nil {
			t.Fatal("one project's lock blocked another", err)
		}
	})
	t.Run("unknown project and private audit", func(t *testing.T) {
		if _, err := applyTransition(ctx, db, transitionCommand(transitionID(999), 999, 1, domain.Suspend), true); !errors.Is(err, domain.ErrNotFound) {
			t.Fatal("unknown project accepted", err)
		}
		var public bool
		if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a WHERE c.oid='platform.project_events'::regclass AND a.grantee=0)`).Scan(&public); err != nil || public {
			t.Fatal("audit exposed to PUBLIC", err)
		}
	})
}
