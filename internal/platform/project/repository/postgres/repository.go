package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

type Repository struct{ db *pgxpool.Pool }

func New(db *pgxpool.Pool) *Repository { return &Repository{db: db} }

const projectColumns = `id::text,slug,name,origin,desired_state,phase,version,generation,created_at,updated_at`

type Binding struct {
	Project       domain.Project
	StorageTarget string
	DatabaseName  string
	CredentialRef string
	SchemaVersion int64
}

func (r *Repository) Read(ctx context.Context, id domain.ID) (domain.Project, error) {
	if !domain.ValidID(id) {
		return domain.Project{}, domain.ErrInvalidProject
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	p, err := scanProject(r.db.QueryRow(ctx, `SELECT `+projectColumns+` FROM platform.projects WHERE id=$1::uuid`, id))
	return p, catalogError(ctx, err)
}

func (r *Repository) Resolve(ctx context.Context, origin string) (Binding, error) {
	if !domain.ValidOrigin(origin) {
		return Binding{}, domain.ErrNotFound
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var b Binding
	p := &b.Project
	err := r.db.QueryRow(ctx, `SELECT `+projectColumns+`,storage_target,database_name,credential_ref,schema_version
		FROM platform.projects WHERE origin=$1 AND desired_state='enabled' AND phase='ready'`, origin).Scan(
		&p.ID, &p.Slug, &p.Name, &p.Origin, &p.DesiredState, &p.Phase, &p.Version, &p.Generation, &p.CreatedAt, &p.UpdatedAt,
		&b.StorageTarget, &b.DatabaseName, &b.CredentialRef, &b.SchemaVersion,
	)
	if err != nil {
		return Binding{}, catalogError(ctx, err)
	}
	return b, nil
}

func scanProject(row interface{ Scan(...any) error }) (domain.Project, error) {
	var p domain.Project
	err := row.Scan(&p.ID, &p.Slug, &p.Name, &p.Origin, &p.DesiredState, &p.Phase, &p.Version, &p.Generation, &p.CreatedAt, &p.UpdatedAt)
	return p, err
}

func catalogError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	// Driver errors may include addresses or credentials; preserve only safe cancellation.
	return errors.Join(domain.ErrUnavailable, ctx.Err())
}
