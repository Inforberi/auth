package postgres

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	"github.com/Inforberi/financial-intelligence/migrations"
)

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
