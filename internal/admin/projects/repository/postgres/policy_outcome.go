package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/sqlerrors"
	policymutation "github.com/Inforberi/financial-intelligence/internal/admin/projects/policy/repository/postgres/mutation"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	schemapostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/schema/postgres"
)

func (r *Repository) ReadAuthPolicyOutcome(ctx context.Context, actor operatordomain.Principal, project, operation domain.ID, registry *projectruntime.Registry) (domain.AuthPolicyOutcome, error) {
	if !domain.ValidID(project) || !domain.ValidID(operation) {
		return domain.AuthPolicyOutcome{}, domain.ErrInvalidProject
	}
	var command domain.AuthPolicyUpdate
	var request []byte
	var key projectruntime.Key
	b := &key.Binding
	err := r.mutate(ctx, actor, operatordomain.SettingsManage, func(ctx context.Context, tx pgx.Tx, _ time.Time) error {
		return sqlerrors.Catalog(ctx, tx.QueryRow(ctx, `SELECT request,realm_id::text,binding->>'target',binding->>'reservation',
            (binding->>'database_oid')::oid,(binding->>'owner_oid')::oid,(binding->>'runtime_oid')::oid,(binding->>'schema')::int,
            version,generation
            FROM platform.project_auth_policy_intents WHERE operation_id=$1 AND project_id=$2 AND actor_id=$3`, operation, project, actor.UserID).
			Scan(&request, &b.RealmID, &b.StorageTarget, &b.ReservationID, &b.DatabaseOID, &b.OwnerOID, &b.RuntimeOID, &b.SchemaVersion, &key.Version, &key.Generation))
	})
	if err != nil {
		return domain.AuthPolicyOutcome{}, err
	}
	if json.Unmarshal(request, &command) != nil || command.ProjectID != project || command.OperationID != operation || command.ExpectedVersion != key.Version || command.ExpectedGeneration != key.Generation {
		return domain.AuthPolicyOutcome{}, domain.ErrConflict
	}
	b.ProjectID = project
	result := domain.AuthPolicyOutcome{OperationID: operation}
	target := domain.DirectoryTarget{ProjectID: project, ExpectedVersion: key.Version, ExpectedGeneration: key.Generation}
	err = r.ReadDirectory(ctx, actor, target, registry, []operatordomain.Permission{operatordomain.SettingsManage}, func(ctx context.Context, tx pgx.Tx) error {
		// Pin to the operation's original binding, not merely today's catalog target.
		if err := schemapostgres.CheckRuntime(ctx, tx, key.Binding); err != nil {
			return err
		}
		binding, err := json.Marshal(key.Binding)
		if err != nil {
			return domain.ErrUnavailable
		}
		result.AuthPolicyResult, result.Committed, err = policymutation.ReadReceipt(ctx, tx, domain.PlatformActor{RealmID: key.Binding.RealmID, UserID: domain.ID(actor.UserID)}, command, binding, request)
		if err != nil || !result.Committed {
			return err
		}
		var found int
		return sqlerrors.Catalog(ctx, r.db.QueryRow(ctx, `SELECT 1 FROM platform.project_auth_policy_admissions WHERE operation_id=$1 AND admission_id=$2`, operation, result.ReceiptAdmissionID).Scan(&found))
	})
	if err != nil {
		return domain.AuthPolicyOutcome{}, err
	}
	return result, nil
}
