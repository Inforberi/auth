package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/sqlerrors"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	schemapostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/schema/postgres"
)

func (r *Repository) ReadDirectory(ctx context.Context, actor operatordomain.Principal, target domain.DirectoryTarget, registry *projectruntime.Registry, permissions []operatordomain.Permission, read func(context.Context, pgx.Tx) error) error {
	return r.ReadDirectoryWithRuntime(ctx, actor, target, registry, permissions, nil, read)
}

type DirectoryRuntime struct {
	Key    projectruntime.Key
	Origin string
}

func (r *Repository) ReadDirectoryWithRuntime(ctx context.Context, actor operatordomain.Principal, target domain.DirectoryTarget, registry *projectruntime.Registry, permissions []operatordomain.Permission, selected *DirectoryRuntime, read func(context.Context, pgx.Tx) error) error {
	if registry == nil || len(permissions) == 0 {
		return domain.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	key := projectruntime.Key{Version: target.ExpectedVersion, Generation: target.ExpectedGeneration}
	var origin string
	guard := func(ctx context.Context, tx pgx.Tx, _ time.Time) error {
		// mutate already holds identity/session/fresh-auth locks for permissions[0].
		for _, permission := range permissions[1:] {
			var found int
			err := tx.QueryRow(ctx, `SELECT 1 FROM platform.operator_permissions WHERE user_id=$1 AND permission_key=$2 FOR SHARE`, actor.UserID, permission).Scan(&found)
			if errors.Is(err, pgx.ErrNoRows) {
				return operatordomain.ErrForbidden
			}
			if err != nil {
				return sqlerrors.Catalog(ctx, err)
			}
		}
		binding, _, err := lockProjectTarget(ctx, tx, target.ProjectID, target.ExpectedVersion, target.ExpectedGeneration)
		if err != nil {
			return err
		}
		if key.Binding.ProjectID != "" && key.Binding != binding {
			return domain.ErrConflict
		}
		key.Binding = binding
		if selected != nil {
			if err := tx.QueryRow(ctx, `SELECT origin FROM platform.projects WHERE id=$1`, target.ProjectID).Scan(&origin); err != nil {
				return sqlerrors.Catalog(ctx, err)
			}
		}
		return nil
	}
	if err := r.mutate(ctx, actor, permissions[0], guard); err != nil {
		return err
	}
	err := registry.Use(ctx, key, func(ctx context.Context, db projectruntime.Database) error {
		tx, err := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if err != nil {
			return sqlerrors.Catalog(ctx, err)
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			defer stop()
			_ = tx.Rollback(cleanup) //nolint:gosec // Preserve the read error; never write project state.
		}()
		if err := schemapostgres.CheckRuntime(ctx, tx, key.Binding); err != nil {
			return err
		}
		if err := read(ctx, tx); err != nil {
			return err
		}
		return sqlerrors.Catalog(ctx, tx.Commit(ctx))
	})
	if err != nil {
		return err
	}
	// Revocation or rebinding during the project read must discard the result.
	if err := r.mutate(ctx, actor, permissions[0], guard); err != nil {
		return err
	}
	if selected != nil {
		*selected = DirectoryRuntime{Key: key, Origin: origin}
	}
	return nil
}
