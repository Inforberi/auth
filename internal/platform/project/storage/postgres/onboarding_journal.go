package postgres

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	"github.com/Inforberi/financial-intelligence/migrations"
)

func (t *Target) lockOnboarding(ctx context.Context, r domain.PreparationReservation, b credentials.Binding) error {
	database, owner, err := r.ResourceNames()
	if err != nil || t.conn == nil || b.RealmID != t.realm || b.StorageTarget != t.name || r.StorageTarget != t.name ||
		b.ProjectID != r.ProjectID || b.ReservationID != r.ReservationID || !domain.ValidID(r.OperationID) ||
		r.Version < 1 || r.Generation < 1 || b.DatabaseOID == 0 || b.OwnerOID == 0 || b.RuntimeOID == 0 || b.SchemaVersion != migrations.AuthVersion {
		return domain.ErrConflict
	}
	if err := t.CheckRuntime(ctx); err != nil {
		return err
	}
	var locked bool
	if err := t.conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(1096111176,1)`).Scan(&locked); err != nil {
		return unavailable(ctx)
	}
	if !locked {
		return ErrBusy
	}
	// The dedicated session keeps the target lock until its caller closes it, also on errors.
	t.prepared = &preparedProject{
		reservation: r, runtimeOID: b.RuntimeOID,
		resources: Resources{Database: database, Owner: owner, DatabaseOID: b.DatabaseOID, OwnerOID: b.OwnerOID},
	}
	return nil
}

func (t *Target) withOnboardingJournal(ctx context.Context, allowPriorEpoch bool, work func(pgx.Tx, string, bool) error) error {
	tx, err := t.conn.Begin(ctx)
	if err != nil {
		return unavailable(ctx)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		_ = tx.Rollback(cleanup) //nolint:gosec // Physical changes and journal state commit together.
	}()
	r, resources := t.prepared.reservation, t.prepared.resources
	var state string
	var operation *string
	var version, generation *int64
	var resourceGeneration int64
	err = tx.QueryRow(ctx, `SELECT onboarding_state,onboarding_operation_id::text,onboarding_version,onboarding_generation,generation
		FROM provisioning.resources WHERE project_id=$1 AND reservation_id=$2 AND database_oid=$3 AND owner_oid=$4
		AND runtime_oid=$5 AND generation<=$6 AND schema_started AND password_fingerprint IS NOT NULL FOR UPDATE`,
		r.ProjectID, r.ReservationID, resources.DatabaseOID, resources.OwnerOID, t.prepared.runtimeOID, r.Generation).
		Scan(&state, &operation, &version, &generation, &resourceGeneration)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrConflict
	}
	if err != nil {
		return unavailable(ctx)
	}
	same := matchesOnboardingEpoch(r, operation, version, generation)
	prior := allowPriorEpoch && version != nil && generation != nil && *version < r.Version && *generation < r.Generation
	if (!allowPriorEpoch && resourceGeneration != r.Generation) || (state != "closed" && !same && !prior) {
		return domain.ErrConflict
	}
	if err := validateOwner(ctx, tx, resources); err != nil {
		return err
	}
	if err := t.checkOnboardingAccess(ctx, tx, state); err != nil {
		return err
	}
	if err := work(tx, state, same); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return unavailable(ctx)
	}
	return nil
}

func matchesOnboardingEpoch(r domain.PreparationReservation, operation *string, version, generation *int64) bool {
	return operation != nil && version != nil && generation != nil &&
		*operation == string(r.OperationID) && *version == r.Version && *generation == r.Generation
}

func (t *Target) checkOnboardingAccess(ctx context.Context, tx pgx.Tx, state string) error {
	r, resources := t.prepared.reservation, t.prepared.resources
	var safe bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_database d JOIN pg_roles role ON role.oid=$1
		WHERE d.oid=$2 AND d.datname=$3 AND d.datdba=$4 AND NOT d.datistemplate
		AND shobj_description(d.oid,'pg_database')=$5 AND d.datacl IS NOT NULL
		AND role.rolname=$6 AND NOT role.rolsuper AND NOT role.rolinherit AND NOT role.rolcreatedb
		AND NOT role.rolcreaterole AND NOT role.rolreplication AND NOT role.rolbypassrls
		AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=role.oid)
		AND NOT EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member
			WHERE m.roleid=role.oid AND member.rolname<>session_user)
		AND EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles executor ON executor.oid=m.member
			WHERE m.roleid=role.oid AND executor.rolname=session_user AND m.admin_option)
		AND pg_has_role(session_user,role.oid,'SET')
		AND d.datallowconn=role.rolcanlogin AND ($7 OR NOT d.datallowconn)
		AND has_database_privilege(role.oid,d.oid,'CONNECT')=d.datallowconn
		AND NOT has_database_privilege(role.oid,d.oid,'CREATE,TEMP')
		AND NOT EXISTS(SELECT 1 FROM aclexplode(d.datacl) a WHERE a.grantee<>d.datdba
			AND NOT (d.datallowconn AND a.grantee=role.oid AND a.privilege_type='CONNECT' AND NOT a.is_grantable)))`,
		t.prepared.runtimeOID, resources.DatabaseOID, resources.Database, resources.OwnerOID, t.databaseMarker(r),
		"authr_"+strings.TrimPrefix(resources.Owner, "autho_"), state != "closed").Scan(&safe)
	if err != nil {
		return unavailable(ctx)
	}
	if !safe {
		return domain.ErrConflict
	}
	return nil
}
