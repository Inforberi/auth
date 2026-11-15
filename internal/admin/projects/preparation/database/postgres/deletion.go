package postgres

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	schemapg "github.com/Inforberi/financial-intelligence/internal/admin/projects/schema/postgres"
)

var ErrDeletionHasUsers = errors.New("project users require explicit confirmation")

func (t *Target) DeleteConfirmed(ctx context.Context, b credentials.Binding, password string, acknowledge, draining, verified, expired bool, seal, certify func(context.Context) error) error {
	if b.RealmID != t.realm || b.StorageTarget != t.name || seal == nil || certify == nil {
		return domain.ErrConflict
	}
	database, owner, err := (domain.PreparationReservation{ProjectID: b.ProjectID, ReservationID: b.ReservationID}).ResourceNames()
	if err != nil {
		return err
	}
	open, missing, err := t.deletionDatabase(ctx, b, database)
	if err != nil {
		return err
	}
	if missing {
		if verified {
			return nil
		}
		return domain.ErrConflict
	}
	identifier := pgx.Identifier{database}.Sanitize()
	if expired {
		if open {
			return nil
		}
		return t.alterDeletionAccess(ctx, owner, identifier, true)
	}
	if !verified {
		if !open {
			if err := t.reopenDrainingDatabase(ctx, b.DatabaseOID, owner, identifier, draining); err != nil {
				return err
			}
		}
		cfg := t.conn.Config().Copy()
		cfg.Database, cfg.User, cfg.Password = database, "authr_"+strings.TrimPrefix(owner, "autho_"), password
		if err := t.verifyDeletion(ctx, b, cfg, owner, identifier, acknowledge, seal, certify); err != nil {
			return err
		}
	} else if open {
		return domain.ErrConflict
	}
	if _, err := t.conn.Exec(ctx, `SET ROLE `+pgx.Identifier{owner}.Sanitize()); err != nil {
		return unavailable(ctx)
	}
	if _, err := t.conn.Exec(ctx, `DROP DATABASE `+identifier); err != nil {
		return unavailable(ctx)
	}
	return nil
}

func (t *Target) deletionDatabase(ctx context.Context, b credentials.Binding, database string) (open, missing bool, err error) {
	var journal bool
	if err := t.conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM provisioning.resources WHERE project_id=$1 AND reservation_id=$2
		AND database_oid=$3 AND owner_oid=$4 AND runtime_oid=$5)`, b.ProjectID, b.ReservationID, b.DatabaseOID, b.OwnerOID, b.RuntimeOID).Scan(&journal); err != nil || !journal {
		return false, false, domain.ErrConflict
	}
	var oid, ownerOID uint32
	err = t.conn.QueryRow(ctx, `SELECT oid,datdba,datallowconn FROM pg_database WHERE datname=$1 AND NOT datistemplate`, database).Scan(&oid, &ownerOID, &open)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, true, nil
	}
	if err != nil || oid != b.DatabaseOID || ownerOID != b.OwnerOID || database == t.conn.Config().Database {
		return false, false, domain.ErrConflict
	}
	return open, false, nil
}

func (t *Target) reopenDrainingDatabase(ctx context.Context, oid uint32, owner, identifier string, draining bool) error {
	if !draining {
		return domain.ErrConflict
	}
	var active bool
	if err := t.conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datid=$1)`, oid).Scan(&active); err != nil {
		return unavailable(ctx)
	}
	if active {
		return domain.ErrConflict
	}
	return t.alterDeletionAccess(ctx, owner, identifier, true)
}

func (t *Target) verifyDeletion(ctx context.Context, b credentials.Binding, cfg *pgx.ConnConfig, owner, identifier string, acknowledge bool, seal, certify func(context.Context) error) error {
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return unavailable(ctx)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		_ = conn.Close(cleanup) //nolint:gosec // Dedicated verifier connection.
	}()
	if err := schemapg.CheckRuntimeConnection(ctx, conn, b); err != nil {
		return err
	}
	if err := seal(ctx); err != nil {
		return err
	}
	if err := t.alterDeletionAccess(ctx, owner, identifier, false); err != nil {
		return err
	}
	// Existing connections may still write after the seal. Certify only once they have drained.
	var others, hasUsers bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datid=$1 AND pid<>pg_backend_pid())`, b.DatabaseOID).Scan(&others); err != nil {
		return unavailable(ctx)
	}
	if others {
		return domain.ErrConflict
	}
	if err := conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.users)`).Scan(&hasUsers); err != nil {
		return unavailable(ctx)
	}
	if hasUsers && !acknowledge {
		if err := t.alterDeletionAccess(ctx, owner, identifier, true); err != nil {
			return err
		}
		return ErrDeletionHasUsers
	}
	return certify(ctx)
}

func (t *Target) alterDeletionAccess(ctx context.Context, owner, identifier string, open bool) error {
	return pgx.BeginFunc(ctx, t.conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+pgx.Identifier{owner}.Sanitize()); err != nil {
			return unavailable(ctx)
		}
		suffix := " false"
		if open {
			suffix = " true"
		}
		if _, err := tx.Exec(ctx, `ALTER DATABASE `+identifier+` ALLOW_CONNECTIONS`+suffix); err != nil {
			return unavailable(ctx)
		}
		return nil
	})
}
