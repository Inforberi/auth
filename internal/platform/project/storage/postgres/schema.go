package postgres

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/deploy"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	"github.com/Inforberi/financial-intelligence/migrations"
)

func (t *Target) InstallSchema(ctx context.Context, authorize func(context.Context) error) (int, error) {
	err := t.withProjectAccess(ctx, authorize, func(check context.Context, project *pgx.Conn) error {
		return t.installProjectSchema(check, project, t.prepared.reservation, t.prepared.resources)
	})
	if err != nil {
		return 0, err
	}
	return migrations.AuthVersion, nil
}

func (t *Target) withProjectAccess(ctx context.Context, authorize func(context.Context) error, work func(context.Context, *pgx.Conn) error) error {
	if t.prepared == nil || authorize == nil {
		return domain.ErrConflict
	}
	t.prepared.schemaReady = false
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if err := authorize(ctx); err != nil {
		return err
	}
	r, resources := t.prepared.reservation, t.prepared.resources
	sealed := false
	// Cleanup is installed before the ambiguous commit that can enable connections.
	defer func() {
		if sealed {
			return
		}
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer stop()
		_ = t.schemaAccess(cleanup, r, resources, false) //nolint:gosec // Explicit final seal below must succeed before success is returned.
	}()
	if err := t.schemaAccess(ctx, r, resources, true); err != nil {
		return err
	}
	cfg := t.conn.Config().Copy()
	cfg.Database = resources.Database
	project, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return unavailable(ctx)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		_ = project.Close(cleanup) //nolint:gosec // Dedicated migration connection, never pooled.
	}()
	// A second connection may resolve DNS differently. Check the shared marker before any DDL there.
	var matching bool
	err = project.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=current_database() AND oid=$1 AND datdba=$2
		AND NOT datistemplate AND shobj_description(oid,'pg_database')=$3)`, resources.DatabaseOID, resources.OwnerOID, t.databaseMarker(r)).Scan(&matching)
	if err != nil {
		return unavailable(ctx)
	}
	if !matching {
		return domain.ErrConflict
	}
	if err := work(ctx, project); err != nil {
		return err
	}
	if err := project.Close(ctx); err != nil {
		return unavailable(ctx)
	}
	if err := t.schemaAccess(ctx, r, resources, false); err != nil {
		return err
	}
	sealed = true
	if err := authorize(ctx); err != nil {
		return err
	}
	t.prepared.schemaReady = true
	return nil
}

func (t *Target) installProjectSchema(ctx context.Context, conn *pgx.Conn, r domain.PreparationReservation, resources Resources) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return unavailable(ctx)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		_ = tx.Rollback(cleanup) //nolint:gosec // Schema, marker and runtime role share one transaction.
	}()
	// Keep schema writers serialized even if the separate maintenance session loses its lock.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(1096111176,2); SET LOCAL ROLE `+pgx.Identifier{resources.Owner}.Sanitize()); err != nil {
		return unavailable(ctx)
	}
	runtime := "authr_" + strings.TrimPrefix(resources.Owner, "autho_")
	grants := deploy.RuntimeGrants(resources.Database, runtime)
	checksum := migrations.ProjectSchemaChecksum(grants)
	var installed bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('project_meta.identity') IS NOT NULL`).Scan(&installed); err != nil {
		return unavailable(ctx)
	}
	if installed {
		if err := t.checkInstalledSchema(ctx, tx, r, resources, runtime, checksum); err != nil {
			return err
		}
	} else {
		var occupied bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)
			OR EXISTS(SELECT 1 FROM pg_namespace WHERE nspname IN ('auth','project_meta','platform'))`, runtime).Scan(&occupied); err != nil {
			return unavailable(ctx)
		}
		if occupied {
			return domain.ErrConflict
		}
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE NONE`); err != nil {
			return unavailable(ctx)
		}
		if _, err := tx.Exec(ctx, `CREATE ROLE `+pgx.Identifier{runtime}.Sanitize()+` NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
			return unavailable(ctx)
		}
		if _, err := tx.Exec(ctx, `GRANT `+pgx.Identifier{runtime}.Sanitize()+` TO SESSION_USER WITH SET TRUE, INHERIT FALSE`); err != nil {
			return unavailable(ctx)
		}
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+pgx.Identifier{resources.Owner}.Sanitize()); err != nil {
			return unavailable(ctx)
		}
		if _, err := tx.Exec(ctx, `SET LOCAL search_path=pg_catalog,public; REVOKE CREATE ON SCHEMA public FROM PUBLIC;`+migrations.InitialAuth()); err != nil {
			return unavailable(ctx)
		}
		if _, err := tx.Exec(ctx, grants+`; REVOKE CONNECT ON DATABASE `+pgx.Identifier{resources.Database}.Sanitize()+` FROM `+pgx.Identifier{runtime}.Sanitize()+`; REVOKE ALL ON SCHEMA auth FROM PUBLIC`); err != nil {
			return unavailable(ctx)
		}
		if err := t.recordInstalledSchema(ctx, tx, r, resources, runtime, checksum); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return unavailable(ctx)
	}
	return nil
}
