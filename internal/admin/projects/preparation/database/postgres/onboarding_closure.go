package postgres

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	preparationpostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/repository/postgres"
)

// CloseOnboarding is also the restart/reconciliation path for opening/open/closing intents.
func (t *Target) CloseOnboarding(ctx context.Context, r domain.PreparationReservation, b credentials.Binding, admission *preparationpostgres.PreparationRepository) error {
	if admission == nil {
		return domain.ErrConflict
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := t.lockOnboarding(ctx, r, b); err != nil {
		return err
	}
	if err := admission.WithdrawOnboarding(ctx, r, b); err != nil {
		return err // An unavailable catalog is not proof that its permission was revoked.
	}
	if err := t.withOnboardingJournal(ctx, true, func(tx pgx.Tx, state string, _ bool) error {
		if state == "closed" {
			return nil
		}
		if err := t.changeOnboardingAccess(ctx, tx, false); err != nil {
			return err
		}
		if state != "closing" {
			if _, err := tx.Exec(ctx, `UPDATE provisioning.resources SET onboarding_state='closing' WHERE project_id=$1`, r.ProjectID); err != nil {
				return unavailable(ctx)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if err := t.drainOnboarding(ctx); err != nil {
		return err
	}
	return t.withOnboardingJournal(ctx, true, func(tx pgx.Tx, state string, _ bool) error {
		if state != "closed" {
			if _, err := tx.Exec(ctx, `UPDATE provisioning.resources SET onboarding_state='closed' WHERE project_id=$1`, r.ProjectID); err != nil {
				return unavailable(ctx)
			}
		}
		return nil
	})
}

func (t *Target) drainOnboarding(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	for {
		count, err := t.terminateOnboardingBatch(ctx)
		if err != nil {
			return err
		}
		if count == 0 {
			var empty bool
			// backend_type is redacted for foreign NOINHERIT sessions; datid/pid/usesysid are not.
			if err := t.conn.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datid=$1)`, t.prepared.resources.DatabaseOID).Scan(&empty); err != nil {
				return unavailable(ctx)
			}
			if !empty {
				return domain.ErrConflict // Do not terminate a foreign/DBA connection.
			}
			return nil
		}
	}
}

func (t *Target) terminateOnboardingBatch(ctx context.Context) (int, error) {
	tx, err := t.conn.Begin(ctx)
	if err != nil {
		return 0, unavailable(ctx)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup) //nolint:gosec // SET LOCAL cannot leak into the maintenance session.
	}()
	// NOINHERIT ADMIN membership alone cannot signal sessions. Act only as this project's runtime.
	runtime := "authr_" + strings.TrimPrefix(t.prepared.resources.Owner, "autho_")
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+pgx.Identifier{runtime}.Sanitize()); err != nil {
		return 0, unavailable(ctx)
	}
	var count int
	var terminated bool
	err = tx.QueryRow(ctx, `SELECT count(*),COALESCE(bool_and(pg_terminate_backend(pid,1000)),true)
		FROM (SELECT pid FROM pg_stat_activity WHERE datid=$1 AND usesysid=$2 LIMIT 128) sessions`,
		t.prepared.resources.DatabaseOID, t.prepared.runtimeOID).Scan(&count, &terminated)
	if err != nil || !terminated {
		return 0, unavailable(ctx)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, unavailable(ctx)
	}
	return count, nil
}
