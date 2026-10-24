package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
)

type RuntimeCredentialReader struct {
	db    *pgxpool.Pool
	realm domain.ID
	codec *credentials.Codec
}

func NewRuntimeCredentialReader(db *pgxpool.Pool, realm domain.ID, codec *credentials.Codec) (*RuntimeCredentialReader, error) {
	if db == nil || !domain.ValidID(realm) || codec == nil {
		return nil, domain.ErrUnavailable
	}
	return &RuntimeCredentialReader{db: db, realm: realm, codec: codec}, nil
}

func (r *RuntimeCredentialReader) CheckRuntime(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var safe bool
	err := r.db.QueryRow(ctx, `SELECT (`+runtimeCredentialProfile+`) AND EXISTS(SELECT 1 FROM platform.operator_realm WHERE id=$1)`, r.realm).Scan(&safe)
	if err != nil {
		return catalogError(ctx, err)
	}
	if !safe {
		return domain.ErrUnavailable
	}
	return nil
}

// This reader has no Auth access or catalog write/DDL privileges. The profile is
// evaluated in the same snapshot as the ciphertext, including on cold retries.
const runtimeCredentialProfile = `current_user=session_user
	AND EXISTS(SELECT 1 FROM pg_roles r WHERE r.rolname=current_user AND NOT r.rolsuper
		AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolreplication AND NOT r.rolbypassrls
		AND NOT r.rolinherit AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=r.oid))
	AND NOT EXISTS(SELECT 1 FROM pg_database WHERE datname=current_database() AND pg_has_role(current_user,datdba,'MEMBER'))
	AND NOT has_database_privilege(current_user,current_database(),'CREATE,TEMP')
	AND NOT has_schema_privilege(current_user,'auth','USAGE,CREATE')
	AND NOT has_schema_privilege(current_user,'platform','CREATE')
	AND NOT has_schema_privilege(current_user,'public','CREATE')
	AND NOT EXISTS(SELECT 1 FROM (VALUES('platform.operator_realm'),('platform.projects'),
		('platform.project_preparations'),('platform.project_secrets')) needed(relation)
		WHERE NOT has_table_privilege(current_user,needed.relation,'SELECT'))
	AND NOT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname IN ('auth','platform') AND pg_has_role(current_user,nspowner,'MEMBER'))
	AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace ns ON ns.oid=c.relnamespace
		WHERE ns.nspname='platform' AND c.relkind IN ('r','p','v')
		AND (pg_has_role(current_user,c.relowner,'MEMBER')
		OR has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES')
		OR has_table_privilege(current_user,c.oid,'DELETE,TRUNCATE,TRIGGER,SELECT WITH GRANT OPTION')))`

func (r *RuntimeCredentialReader) LoadDatabaseCredential(ctx context.Context, key projectruntime.Key) (credentials.DatabaseCredential, error) {
	b := key.Binding
	if !key.Valid() || b.RealmID != r.realm {
		return credentials.DatabaseCredential{}, domain.ErrConflict
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var version int
	var keyID string
	var payload []byte
	err := r.db.QueryRow(ctx, `WITH wanted AS (SELECT $1::uuid AS realm_id,$2::uuid AS project_id,$3::uuid AS reservation_id,
		$4::text AS storage_target,$5::oid AS database_oid,$6::oid AS owner_oid,$7::oid AS runtime_oid,
		$8::int AS schema_version,$9::bigint AS version,$10::bigint AS generation)
		SELECT s.format_version,s.key_id,s.ciphertext FROM wanted CROSS JOIN `+runtimeSnapshotRelations+`
		WHERE `+runtimeSnapshotPredicate+` AND (`+runtimeCredentialProfile+`)`, b.RealmID, b.ProjectID, b.ReservationID, b.StorageTarget,
		b.DatabaseOID, b.OwnerOID, b.RuntimeOID, b.SchemaVersion, key.Version, key.Generation).Scan(&version, &keyID, &payload)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return credentials.DatabaseCredential{}, domain.ErrConflict
		}
		return credentials.DatabaseCredential{}, catalogError(ctx, err)
	}
	defer clear(payload)
	return r.codec.OpenDatabase(b, version, keyID, payload)
}
