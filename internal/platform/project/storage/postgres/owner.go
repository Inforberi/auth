package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

func (t *Target) reserveOwner(ctx context.Context, r domain.PreparationReservation, resources *Resources) error {
	tx, err := t.conn.Begin(ctx)
	if err != nil {
		return unavailable(ctx)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup) //nolint:gosec // Commit closes the transaction; preserve the original error.
	}()
	var reservation string
	var generation int64
	var onboarding string
	err = tx.QueryRow(ctx, `SELECT reservation_id::text,owner_oid,generation,onboarding_state
		FROM provisioning.resources WHERE project_id=$1 FOR UPDATE`, r.ProjectID).Scan(&reservation, &resources.OwnerOID, &generation, &onboarding)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		var occupied bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)
			OR EXISTS(SELECT 1 FROM pg_database WHERE datname=$2)`, resources.Owner, resources.Database).Scan(&occupied); err != nil {
			return unavailable(ctx)
		}
		if occupied {
			return domain.ErrConflict
		}
		owner := pgx.Identifier{resources.Owner}.Sanitize()
		if _, err := tx.Exec(ctx, `CREATE ROLE `+owner+` NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
			return unavailable(ctx)
		}
		// PostgreSQL 18 grants ADMIN but not SET to the CREATEROLE creator automatically.
		if _, err := tx.Exec(ctx, `GRANT `+owner+` TO CURRENT_USER WITH SET TRUE, INHERIT FALSE`); err != nil {
			return unavailable(ctx)
		}
		if err := tx.QueryRow(ctx, `SELECT oid FROM pg_roles WHERE rolname=$1`, resources.Owner).Scan(&resources.OwnerOID); err != nil {
			return unavailable(ctx)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO provisioning.resources(project_id,reservation_id,owner_oid,generation)
			VALUES($1,$2,$3,$4)`, r.ProjectID, r.ReservationID, resources.OwnerOID, r.Generation); err != nil {
			return unavailable(ctx)
		}
	case err != nil:
		return unavailable(ctx)
	case reservation != string(r.ReservationID) || generation > r.Generation || onboarding != "closed":
		return domain.ErrConflict
	default:
		if err := validateOwner(ctx, tx, *resources); err != nil {
			return err
		}
		if generation < r.Generation {
			if _, err := tx.Exec(ctx, `UPDATE provisioning.resources SET generation=$2 WHERE project_id=$1`, r.ProjectID, r.Generation); err != nil {
				return unavailable(ctx)
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return unavailable(ctx)
	}
	return nil
}

func validateOwner(ctx context.Context, tx pgx.Tx, resources Resources) error {
	var safe bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE oid=$1 AND rolname=$2
		AND NOT rolcanlogin AND NOT rolsuper AND NOT rolinherit AND NOT rolcreatedb AND NOT rolcreaterole
		AND NOT rolreplication AND NOT rolbypassrls AND pg_has_role(current_user,oid,'SET'))
		AND NOT EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=$1)
		AND NOT EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member
			WHERE m.roleid=$1 AND member.rolname<>current_user)`, resources.OwnerOID, resources.Owner).Scan(&safe)
	if err != nil {
		return unavailable(ctx)
	}
	if !safe {
		return domain.ErrConflict
	}
	return nil
}
