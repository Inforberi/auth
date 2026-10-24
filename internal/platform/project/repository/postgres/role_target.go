package postgres

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	"github.com/Inforberi/financial-intelligence/migrations"
)

func lockRoleTarget(ctx context.Context, tx pgx.Tx, command domain.RoleCreation) (credentials.Binding, []byte, error) {
	b := credentials.Binding{ProjectID: command.ProjectID}
	var snapshot []byte
	// Lifecycle writers lock the project first; runtime cannot alter private metadata.
	err := tx.QueryRow(ctx, `SELECT realm.id::text,prep.reservation_id::text,p.storage_target,
		s.database_oid,s.owner_oid,s.runtime_oid,s.schema_version,jsonb_build_object(
		'target',p.storage_target,'database',p.database_name,'reservation',s.reservation_id,
		'database_oid',s.database_oid,'owner_oid',s.owner_oid,'runtime_oid',s.runtime_oid,'schema',s.schema_version)
		FROM platform.projects p
		JOIN platform.project_preparations prep ON prep.project_id=p.id AND prep.secrets_created
		JOIN platform.project_secrets s ON s.project_id=p.id AND s.reservation_id=prep.reservation_id
			AND s.storage_target=prep.storage_target AND s.storage_target=p.storage_target AND s.schema_version=p.schema_version
		CROSS JOIN platform.operator_realm realm
		WHERE p.id=$1 AND p.version=$2 AND p.generation=$3 AND p.desired_state='enabled' AND p.phase='ready'
		AND realm.initialized_at IS NOT NULL AND p.database_name='authp_'||replace(p.id::text,'-','')
		FOR SHARE OF p`, command.ProjectID, command.ExpectedVersion, command.ExpectedGeneration).Scan(
		&b.RealmID, &b.ReservationID, &b.StorageTarget, &b.DatabaseOID, &b.OwnerOID, &b.RuntimeOID, &b.SchemaVersion, &snapshot,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return credentials.Binding{}, nil, domain.ErrConflict
	}
	return b, snapshot, catalogError(ctx, err)
}

// Identity check on the actual transaction connection; catalog metadata alone
// cannot detect a pool connected to a different project. This is not admission.
func checkRoleTarget(ctx context.Context, tx pgx.Tx, b credentials.Binding) error {
	database, owner, err := (domain.PreparationReservation{ProjectID: b.ProjectID, ReservationID: b.ReservationID}).ResourceNames()
	if err != nil || !domain.ValidStorageTarget(b.StorageTarget) || b.SchemaVersion != migrations.AuthVersion ||
		b.DatabaseOID == 0 || b.OwnerOID == 0 || b.RuntimeOID == 0 {
		return domain.ErrConflict
	}
	marker := "auth-project:" + string(b.RealmID) + ":" + string(b.ProjectID) + ":" + string(b.ReservationID)
	var same bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_database d JOIN pg_roles r ON r.rolname=session_user
		JOIN pg_roles owner ON owner.oid=d.datdba
		WHERE d.datname=current_database() AND d.datname=$1 AND d.oid=$2 AND d.datdba=$3
		AND d.datallowconn AND NOT d.datistemplate AND shobj_description(d.oid,'pg_database')=$4
		AND owner.rolname=$5 AND NOT owner.rolcanlogin AND r.oid=$6 AND r.rolname=$7
		AND current_user=session_user AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolinherit
		AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolreplication AND NOT r.rolbypassrls
		AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=r.oid)
		AND NOT has_database_privilege(r.oid,d.oid,'CREATE,TEMP')
		AND NOT has_schema_privilege(r.oid,'auth','CREATE')
		AND EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='auth' AND nspowner=$3))`,
		database, b.DatabaseOID, b.OwnerOID, marker, owner, b.RuntimeOID, "authr_"+strings.TrimPrefix(owner, "autho_")).Scan(&same)
	if err != nil {
		return catalogError(ctx, err)
	}
	if !same {
		return domain.ErrConflict
	}
	return nil
}
