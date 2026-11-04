package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
)

const schemaAccessGuard = `SELECT EXISTS(SELECT 1 FROM provisioning.resources s JOIN pg_database db ON db.oid=s.database_oid
	WHERE s.project_id=$1 AND s.reservation_id=$2 AND s.owner_oid=$3 AND s.database_oid=$4
	AND (NOT $5 OR s.schema_started) AND db.datdba=s.owner_oid AND NOT db.datistemplate AND db.datacl IS NOT NULL
	AND (shobj_description(db.oid,'pg_database')=$6 OR (NOT $5 AND shobj_description(db.oid,'pg_database') IS NULL))
	AND NOT EXISTS(SELECT 1 FROM aclexplode(db.datacl) acl WHERE acl.grantee<>s.owner_oid AND NOT
		(acl.grantee=(SELECT oid FROM pg_roles WHERE rolname=session_user) AND acl.privilege_type='CONNECT')))`

func (t *Target) databaseMarker(r domain.PreparationReservation) string {
	return "auth-project:" + string(t.realm) + ":" + string(r.ProjectID) + ":" + string(r.ReservationID)
}

// schema_started and CONNECT/ALLOW_CONNECTIONS commit together in the maintenance database.
func (t *Target) schemaAccess(ctx context.Context, r domain.PreparationReservation, resources Resources, open bool) error {
	tx, err := t.conn.Begin(ctx)
	if err != nil {
		return unavailable(ctx)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		_ = tx.Rollback(cleanup) //nolint:gosec // Preserve the original error; SET LOCAL cannot escape.
	}()
	if open {
		var safe bool
		if err := tx.QueryRow(ctx, schemaAccessGuard, r.ProjectID, r.ReservationID, resources.OwnerOID, resources.DatabaseOID, false, t.databaseMarker(r)).Scan(&safe); err != nil {
			return unavailable(ctx)
		}
		if !safe {
			return domain.ErrConflict
		}
		var started bool
		if err := tx.QueryRow(ctx, `SELECT schema_started FROM provisioning.resources
			WHERE project_id=$1 AND reservation_id=$2 AND database_oid=$3 AND owner_oid=$4 AND generation=$5 FOR UPDATE`,
			r.ProjectID, r.ReservationID, resources.DatabaseOID, resources.OwnerOID, r.Generation).Scan(&started); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return domain.ErrConflict
			}
			return unavailable(ctx)
		}
		if !started {
			if _, err := tx.Exec(ctx, `UPDATE provisioning.resources SET schema_started=true WHERE project_id=$1`, r.ProjectID); err != nil {
				return unavailable(ctx)
			}
		}
	}
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+pgx.Identifier{resources.Owner}.Sanitize()); err != nil {
		return unavailable(ctx)
	}
	database := pgx.Identifier{resources.Database}.Sanitize()
	statements := []string{`ALTER DATABASE ` + database + ` ALLOW_CONNECTIONS false`, `REVOKE CONNECT ON DATABASE ` + database + ` FROM SESSION_USER`}
	if open {
		var comment string
		if err := tx.QueryRow(ctx, `SELECT format('COMMENT ON DATABASE %I IS %L',$1::text,$2::text)`, resources.Database, t.databaseMarker(r)).Scan(&comment); err != nil {
			return unavailable(ctx)
		}
		if _, err := tx.Exec(ctx, comment); err != nil {
			return unavailable(ctx)
		}
		statements = []string{`GRANT CONNECT ON DATABASE ` + database + ` TO SESSION_USER`, `ALTER DATABASE ` + database + ` ALLOW_CONNECTIONS true`}
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement); err != nil {
			return unavailable(ctx)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return unavailable(ctx)
	}
	return nil
}

func (t *Target) recoverSchemaAccess(ctx context.Context, r domain.PreparationReservation, resources Resources) error {
	var safe bool
	err := t.conn.QueryRow(ctx, schemaAccessGuard,
		r.ProjectID, r.ReservationID, resources.OwnerOID, resources.DatabaseOID, true, t.databaseMarker(r)).Scan(&safe)
	if err != nil {
		return unavailable(ctx)
	}
	if !safe {
		return domain.ErrConflict
	}
	return t.schemaAccess(ctx, r, resources, false)
}
