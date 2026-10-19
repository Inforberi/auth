package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

var (
	ErrUnavailable = errors.New("project storage unavailable")
	ErrBusy        = errors.New("project storage preparation already running")
)

type Target struct {
	conn     *pgx.Conn
	realm    domain.ID
	name     string
	prepared *preparedProject
}

type preparedProject struct {
	reservation domain.PreparationReservation
	resources   Resources
	runtimeOID  uint32
	schemaReady bool
}

type Resources struct {
	Database    string
	Owner       string
	DatabaseOID uint32
	OwnerOID    uint32
}

// New borrows a dedicated connection, never a connection used by HTTP or a pool.
func New(conn *pgx.Conn, realm domain.ID, name string) (*Target, error) {
	if conn == nil || !domain.ValidID(realm) || !domain.ValidStorageTarget(name) {
		return nil, ErrUnavailable
	}
	return &Target{conn: conn, realm: realm, name: name}, nil
}

func (t *Target) CheckRuntime(ctx context.Context) error {
	var allowed bool
	err := t.conn.QueryRow(ctx, `SELECT current_user=session_user
		AND current_setting('server_version_num')::int>=180000
		AND EXISTS(SELECT 1 FROM provisioning.target WHERE realm_id=$1 AND target=$2)
		AND EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND rolcreatedb AND rolcreaterole
			AND NOT rolsuper AND NOT rolreplication AND NOT rolbypassrls AND NOT rolinherit)
		AND NOT EXISTS(SELECT 1 FROM pg_roles r WHERE r.rolname<>current_user
			AND pg_has_role(current_user,r.oid,'MEMBER')
			AND (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls OR r.rolname LIKE 'pg\_%'))
		AND NOT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname IN ('auth','platform'))
		AND NOT EXISTS(SELECT 1 FROM pg_database WHERE datname=current_database() AND pg_has_role(current_user,datdba,'MEMBER'))
		AND NOT has_database_privilege(current_user,current_database(),'CREATE')
		AND NOT has_schema_privilege(current_user,'public','CREATE')
		AND NOT has_schema_privilege(current_user,'provisioning','CREATE')
		AND NOT has_table_privilege(current_user,'provisioning.target','INSERT,UPDATE,DELETE,TRUNCATE')
		AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['singleton','realm_id','target']) col
			WHERE has_column_privilege(current_user,'provisioning.target',col,'INSERT,UPDATE'))
		AND NOT has_table_privilege(current_user,'provisioning.resources','DELETE,TRUNCATE')
		AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['project_id','reservation_id','owner_oid','created_at']) col
			WHERE has_column_privilege(current_user,'provisioning.resources',col,'UPDATE'))
		AND NOT has_column_privilege(current_user,'provisioning.resources','database_oid','INSERT')
		AND NOT has_column_privilege(current_user,'provisioning.resources','created_at','INSERT')
		AND NOT has_column_privilege(current_user,'provisioning.resources','schema_started','INSERT')
		AND has_table_privilege(current_user,'provisioning.target','SELECT')
		AND has_table_privilege(current_user,'provisioning.resources','SELECT')
		AND has_column_privilege(current_user,'provisioning.resources','database_oid','UPDATE')
		AND has_column_privilege(current_user,'provisioning.resources','generation','UPDATE')
		AND has_column_privilege(current_user,'provisioning.resources','schema_started','UPDATE')
		AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['project_id','reservation_id','owner_oid','generation']) col
			WHERE NOT has_column_privilege(current_user,'provisioning.resources',col,'INSERT'))`, t.realm, t.name).Scan(&allowed)
	if err != nil || !allowed {
		return unavailable(ctx)
	}
	return nil
}

// Prepare leaves a sealed database, not a ready Auth runtime. The caller closes the connection.
func (t *Target) Prepare(ctx context.Context, r domain.PreparationReservation) (Resources, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	database, owner, err := r.ResourceNames()
	if err != nil || r.StorageTarget != t.name || r.Generation < 1 {
		return Resources{}, domain.ErrConflict
	}
	if err := t.CheckRuntime(ctx); err != nil {
		return Resources{}, err
	}
	// One DDL operation per target; the same session holds the lock through CREATE DATABASE.
	// No unlock/reuse: even an ambiguous timeout ends with connection close, never a pooled session.
	var locked bool
	if err := t.conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(1096111176, 1)`).Scan(&locked); err != nil {
		return Resources{}, unavailable(ctx)
	}
	if !locked {
		return Resources{}, ErrBusy
	}
	resources := Resources{Database: database, Owner: owner}
	if err := t.reserveOwner(ctx, r, &resources); err != nil {
		return Resources{}, err
	}
	if err := t.prepareDatabase(ctx, r, &resources); err != nil {
		return Resources{}, err
	}
	t.prepared = &preparedProject{reservation: r, resources: resources}
	return resources, nil
}

func unavailable(ctx context.Context) error {
	return errors.Join(ErrUnavailable, ctx.Err())
}
