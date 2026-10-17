package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/access/service"
)

func (r *Repository) transaction(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup) //nolint:gosec // Preserve the operation error; commit already closes the transaction.
	}()
	// Serialize rare access mutations, not reads, to keep delegation checks current across role edits.
	if err := LockAccessChanges(ctx, tx); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return mapConflict(err)
	}
	return mapConflict(tx.Commit(ctx))
}

func mapConflict(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && (pgErr.Code == "23505" || pgErr.Code == "40001" || pgErr.Code == "40P01") {
		return domain.ErrConflict
	}
	return err
}

func requireActor(ctx context.Context, tx pgx.Tx, actor service.Principal, target string) error {
	_, err := lockActor(ctx, tx, actor, target)
	return err
}

func lockActor(ctx context.Context, tx pgx.Tx, actor service.Principal, target string) (time.Time, error) {
	rows, err := tx.Query(ctx, `SELECT id FROM auth.users WHERE id=$1 OR id=NULLIF($2,'')::uuid ORDER BY id FOR UPDATE`, actor.UserID, target)
	if err != nil {
		return time.Time{}, err
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return time.Time{}, err
	}
	var deadline time.Time
	err = tx.QueryRow(ctx, `SELECT LEAST(s.expires_at,s.absolute_expires_at,
		s.password_verified_at+interval '5 minutes',s.mfa_verified_at+interval '5 minutes') FROM auth.role_bound_sessions s
		JOIN auth.users u ON u.id=s.user_id AND u.auth_version=s.auth_version
		WHERE s.user_id=$1 AND s.token_hash=$2 AND s.revoked_at IS NULL
		AND u.status='active' AND u.deleted_at IS NULL
		AND s.expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp()
		AND s.password_verified_at<=clock_timestamp()
		AND s.password_verified_at>clock_timestamp()-interval '5 minutes'
		AND s.mfa_verified_at<=clock_timestamp()
		AND s.mfa_verified_at>clock_timestamp()-interval '5 minutes'
		AND EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=s.user_id)
		FOR UPDATE OF s`, actor.UserID, actor.TokenHash).Scan(&deadline)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, domain.ErrFreshAuthRequired
	}
	return deadline, err
}

func requireDelegation(ctx context.Context, tx pgx.Tx, actor service.Principal, management domain.PermissionKey, permissions []domain.PermissionKey) error {
	keys := make([]string, 0, len(permissions)+1)
	keys = append(keys, string(management))
	for _, key := range permissions {
		keys = append(keys, string(key))
	}
	var permitted bool
	err := tx.QueryRow(ctx, `SELECT NOT EXISTS (
		SELECT 1 FROM unnest($2::text[]) required(key)
		WHERE NOT EXISTS (
			SELECT 1 FROM auth.user_roles ur JOIN auth.role_permissions rp ON rp.role_id=ur.role_id
			WHERE ur.user_id=$1 AND rp.permission_key=required.key
		)
	)`, actor.UserID, keys).Scan(&permitted)
	if err != nil {
		return err
	}
	if !permitted {
		return domain.ErrForbidden
	}
	return nil
}

func recordAudit(ctx context.Context, tx pgx.Tx, actor service.Principal, role domain.Role, event, target string, version *int64) error {
	snapshot, err := json.Marshal(role)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO auth.access_audit(actor_id,target_id,role_id,event,role_version,access_version,role_snapshot)
		VALUES ($1,NULLIF($2,'')::uuid,$3,$4,$5,$6,$7)`, actor.UserID, target, role.ID, event, role.Version, version, snapshot)
	return err
}
