package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

// InstallPassword keeps the database sealed and the runtime NOLOGIN, including on late authority loss.
func (t *Target) InstallPassword(ctx context.Context, value credentials.DatabaseCredential, authorize func(context.Context) error) error {
	binding, err := t.SecretsBinding()
	if err != nil || authorize == nil || value.Binding() != binding || value.Password() == "" {
		return domain.ErrConflict
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := t.CheckRuntime(ctx); err != nil {
		return err
	}
	if err := authorize(ctx); err != nil {
		return err
	}
	tx, err := t.conn.Begin(ctx)
	if err != nil {
		return unavailable(ctx)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		_ = tx.Rollback(cleanup) //nolint:gosec // Password and journal are atomic; preserve the operation error.
	}()
	if err := t.applyPassword(ctx, tx, value, binding); err != nil {
		return err
	}
	if err := authorize(ctx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return unavailable(ctx)
	}
	return authorize(ctx)
}

func (t *Target) applyPassword(ctx context.Context, tx pgx.Tx, value credentials.DatabaseCredential, binding credentials.Binding) error {
	r, resources := t.prepared.reservation, t.prepared.resources
	var runtimeOID *uint32
	var fingerprint []byte
	err := tx.QueryRow(ctx, `SELECT runtime_oid,password_fingerprint FROM provisioning.resources
		WHERE project_id=$1 AND reservation_id=$2 AND owner_oid=$3 AND database_oid=$4 AND generation=$5 AND schema_started FOR UPDATE`,
		r.ProjectID, r.ReservationID, resources.OwnerOID, resources.DatabaseOID, r.Generation).Scan(&runtimeOID, &fingerprint)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrConflict
	}
	if err != nil {
		return unavailable(ctx)
	}
	runtime := "authr_" + strings.TrimPrefix(resources.Owner, "autho_")
	if err := t.checkPasswordTarget(ctx, tx, runtime, binding); err != nil {
		return err
	}
	expected := sha256.Sum256([]byte(value.Password()))
	switch {
	case runtimeOID != nil:
		if *runtimeOID != binding.RuntimeOID || subtle.ConstantTimeCompare(fingerprint, expected[:]) != 1 {
			return domain.ErrConflict
		}
	case fingerprint != nil:
		return domain.ErrConflict
	default:
		verifier, err := passwordVerifier(value.Password())
		if err != nil {
			return err
		}
		// The verifier contains only fixed syntax/base64. Never put the original password in SQL.
		if _, err := tx.Exec(ctx, `ALTER ROLE `+pgx.Identifier{runtime}.Sanitize()+` NOLOGIN PASSWORD '`+verifier+`'`); err != nil {
			return unavailable(ctx)
		}
		if err := t.checkPasswordTarget(ctx, tx, runtime, binding); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE provisioning.resources SET runtime_oid=$2,password_fingerprint=$3 WHERE project_id=$1`,
			r.ProjectID, binding.RuntimeOID, expected[:]); err != nil {
			return unavailable(ctx)
		}
	}
	return nil
}

type passwordTargetQuery interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (t *Target) checkPasswordTarget(ctx context.Context, db passwordTargetQuery, runtime string, binding credentials.Binding) error {
	var safe bool
	err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_database db JOIN pg_roles role ON role.oid=$1
		WHERE db.oid=$2 AND db.datname=$3 AND db.datdba=$4 AND NOT db.datallowconn AND NOT db.datistemplate
		AND shobj_description(db.oid,'pg_database')=$5 AND db.datacl IS NOT NULL
		AND NOT EXISTS(SELECT 1 FROM aclexplode(db.datacl) acl WHERE acl.grantee<>db.datdba)
		AND role.rolname=$6 AND NOT role.rolcanlogin AND NOT role.rolsuper AND NOT role.rolinherit
		AND NOT role.rolcreatedb AND NOT role.rolcreaterole AND NOT role.rolreplication AND NOT role.rolbypassrls
		AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=role.oid)
		AND NOT EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member
			WHERE m.roleid=role.oid AND member.rolname<>session_user)
		AND EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles executor ON executor.oid=m.member
			WHERE m.roleid=role.oid AND executor.rolname=session_user AND m.admin_option)
		AND NOT has_database_privilege(role.oid,db.oid,'CONNECT,CREATE,TEMP'))`,
		binding.RuntimeOID, binding.DatabaseOID, t.prepared.resources.Database, binding.OwnerOID, t.databaseMarker(t.prepared.reservation), runtime).Scan(&safe)
	if err != nil {
		return unavailable(ctx)
	}
	if !safe {
		return domain.ErrConflict
	}
	return nil
}
