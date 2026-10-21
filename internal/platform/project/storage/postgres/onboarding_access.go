package postgres

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

func (t *Target) beginOnboarding(ctx context.Context, authorize func(context.Context) error) error {
	return t.withOnboardingJournal(ctx, false, func(tx pgx.Tx, state string, same bool) error {
		if state == "closing" {
			return domain.ErrConflict
		}
		if err := authorize(ctx); err != nil {
			return err
		}
		if same && state != "closed" {
			return nil
		}
		r := t.prepared.reservation
		_, err := tx.Exec(ctx, `UPDATE provisioning.resources SET onboarding_state='opening',onboarding_operation_id=$2,
			onboarding_version=$3,onboarding_generation=$4 WHERE project_id=$1`, r.ProjectID, r.OperationID, r.Version, r.Generation)
		if err != nil {
			return unavailable(ctx)
		}
		return nil
	})
}

func (t *Target) openOnboarding(ctx context.Context, authorize func(context.Context) error) error {
	return t.withOnboardingJournal(ctx, false, func(tx pgx.Tx, state string, same bool) error {
		if !same || (state != "opening" && state != "open") {
			return domain.ErrConflict
		}
		if err := authorize(ctx); err != nil {
			return err
		}
		if state == "open" {
			return nil
		}
		if err := t.changeOnboardingAccess(ctx, tx, true); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE provisioning.resources SET onboarding_state='open' WHERE project_id=$1`, t.prepared.reservation.ProjectID)
		if err != nil {
			return unavailable(ctx)
		}
		return authorize(ctx)
	})
}

func (t *Target) changeOnboardingAccess(ctx context.Context, tx pgx.Tx, open bool) error {
	resources := t.prepared.resources
	runtime := pgx.Identifier{"authr_" + strings.TrimPrefix(resources.Owner, "autho_")}.Sanitize()
	role := `ALTER ROLE ` + runtime + ` NOLOGIN`
	if open {
		role = `ALTER ROLE ` + runtime + ` LOGIN`
	}
	if _, err := tx.Exec(ctx, role); err != nil {
		return unavailable(ctx)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+pgx.Identifier{resources.Owner}.Sanitize()); err != nil {
		return unavailable(ctx)
	}
	database := pgx.Identifier{resources.Database}.Sanitize()
	statements := []string{`ALTER DATABASE ` + database + ` ALLOW_CONNECTIONS false`, `REVOKE CONNECT ON DATABASE ` + database + ` FROM ` + runtime}
	if open {
		statements = []string{`GRANT CONNECT ON DATABASE ` + database + ` TO ` + runtime, `ALTER DATABASE ` + database + ` ALLOW_CONNECTIONS true`}
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement); err != nil {
			return unavailable(ctx)
		}
	}
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE NONE`); err != nil {
		return unavailable(ctx)
	}
	return nil
}
