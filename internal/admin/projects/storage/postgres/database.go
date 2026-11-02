package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
)

func (t *Target) prepareDatabase(ctx context.Context, r domain.PreparationReservation, resources *Resources) error {
	var recordedOID *uint32
	if err := t.conn.QueryRow(ctx, `SELECT database_oid FROM provisioning.resources WHERE project_id=$1`, r.ProjectID).Scan(&recordedOID); err != nil {
		return unavailable(ctx)
	}
	var owner uint32
	var sealed bool
	err := t.conn.QueryRow(ctx, `SELECT oid,datdba,NOT datallowconn AND NOT datistemplate
		FROM pg_database WHERE datname=$1`, resources.Database).Scan(&resources.DatabaseOID, &owner, &sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		if recordedOID != nil {
			return domain.ErrConflict
		}
		statement := `CREATE DATABASE ` + pgx.Identifier{resources.Database}.Sanitize() + ` WITH OWNER ` +
			pgx.Identifier{resources.Owner}.Sanitize() + ` TEMPLATE template0 ALLOW_CONNECTIONS false`
		if _, err := t.conn.Exec(ctx, statement); err != nil {
			// Lost replies are reconciled by the next explicit attempt under the target lock.
			return unavailable(ctx)
		}
		err = t.conn.QueryRow(ctx, `SELECT oid,datdba,NOT datallowconn AND NOT datistemplate
			FROM pg_database WHERE datname=$1`, resources.Database).Scan(&resources.DatabaseOID, &owner, &sealed)
	}
	if err != nil {
		return unavailable(ctx)
	}
	if owner != resources.OwnerOID || (recordedOID != nil && *recordedOID != resources.DatabaseOID) {
		return domain.ErrConflict
	}
	if !sealed {
		if recordedOID == nil {
			return domain.ErrConflict
		}
		if err := t.recoverSchemaAccess(ctx, r, *resources); err != nil {
			return err
		}
	}
	// SET role is granted only to this executor. NOLOGIN + closed database protect the crash window.
	if err := t.sealPrivileges(ctx, *resources); err != nil {
		return err
	}
	if recordedOID == nil {
		if _, err := t.conn.Exec(ctx, `UPDATE provisioning.resources SET database_oid=$2 WHERE project_id=$1 AND database_oid IS NULL`,
			r.ProjectID, resources.DatabaseOID); err != nil {
			return unavailable(ctx)
		}
	}
	return nil
}

func (t *Target) sealPrivileges(ctx context.Context, resources Resources) error {
	tx, err := t.conn.Begin(ctx)
	if err != nil {
		return unavailable(ctx)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup) //nolint:gosec // SET LOCAL ROLE never escapes this transaction.
	}()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+pgx.Identifier{resources.Owner}.Sanitize()); err != nil {
		return unavailable(ctx)
	}
	if _, err := tx.Exec(ctx, `REVOKE ALL ON DATABASE `+pgx.Identifier{resources.Database}.Sanitize()+` FROM PUBLIC`); err != nil {
		return unavailable(ctx)
	}
	if err := tx.Commit(ctx); err != nil {
		return unavailable(ctx)
	}
	return nil
}
