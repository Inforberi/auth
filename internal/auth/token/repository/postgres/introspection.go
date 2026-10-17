package postgres

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

// Introspect takes the same Access -> user -> session -> policy snapshot as issuance.
// It performs no sliding refresh, per-token audit insert or remote I/O under locks.
func (r *Repository) Introspect(ctx context.Context, claims authjwt.Claims, scope []accessdomain.PermissionKey) ([]accessdomain.PermissionKey, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup) //nolint:gosec // Preserve the decision/commit error.
	}()
	if err := accesspostgres.LockAccessSnapshot(ctx, tx); err != nil {
		return nil, err
	}
	if err := introspectionAuthority(ctx, tx, claims); err != nil {
		return nil, err
	}
	var effective []accessdomain.PermissionKey
	err = tx.QueryRow(ctx, `SELECT ARRAY(SELECT needed.key FROM unnest($2::text[]) needed(key)
		WHERE EXISTS(SELECT 1 FROM auth.user_roles ur JOIN auth.role_permissions rp ON rp.role_id=ur.role_id
		WHERE ur.user_id=$1 AND rp.permission_key=needed.key) ORDER BY needed.key COLLATE "C")`, claims.Subject, scope).Scan(&effective)
	if err != nil {
		return nil, err
	}
	if claims.ExpiresAt <= time.Now().Unix() {
		return nil, authjwt.ErrInvalidToken
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return effective, nil
}

func introspectionAuthority(ctx context.Context, tx pgx.Tx, claims authjwt.Claims) error {
	input := service.ExchangeInput{SessionID: claims.SessionID}
	input.Actor.UserID = accountdomain.UserID(claims.Subject)
	var version int64
	err := tx.QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1 AND status='active' AND deleted_at IS NULL FOR SHARE`, claims.Subject).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && version != claims.AuthVersion {
		return authjwt.ErrInvalidToken
	}
	if err != nil {
		return err
	}
	var profile string
	err = tx.QueryRow(ctx, `SELECT token_hash,credential_profile FROM auth.sessions WHERE id=$1 AND user_id=$2 FOR SHARE`, claims.SessionID, claims.Subject).Scan(&input.Actor.TokenHash, &profile)
	if errors.Is(err, pgx.ErrNoRows) {
		return authjwt.ErrInvalidToken
	}
	if err != nil {
		return err
	}
	if profile == "api" {
		if err := introspectionFamily(ctx, tx, claims); err != nil {
			return err
		}
	}
	proof, _, err := sessionProof(ctx, tx, input, profile, version)
	if errors.Is(err, sessiondomain.ErrSessionNotFound) || errors.Is(err, sessiondomain.ErrMFARequired) || errors.Is(err, accountdomain.ErrEmailUnverified) {
		return authjwt.ErrInvalidToken
	}
	if err != nil {
		return err
	}
	if !matchesAccessProof(claims, proof) {
		return authjwt.ErrInvalidToken
	}
	return nil
}

func matchesAccessProof(claims authjwt.Claims, proof service.SessionProof) bool {
	method := map[string]string{"password": "pwd", "emailotp": "emailotp", "oidc": "oidc"}[proof.Method]
	if len(claims.Methods) == 0 || claims.Methods[0] != method || claims.AuthTime != proof.VerifiedAt.Unix() ||
		claims.AuthVersion != proof.AuthVersion || claims.ExpiresAt > proof.Deadline.Unix() {
		return false
	}
	if claims.MFATime == nil {
		return proof.MFAVerifiedAt == nil
	}
	return proof.MFAVerifiedAt != nil && *claims.MFATime == proof.MFAVerifiedAt.Unix()
}

func introspectionFamily(ctx context.Context, tx pgx.Tx, claims authjwt.Claims) error {
	var valid bool
	err := tx.QueryRow(ctx, `SELECT revoked_at IS NULL AND absolute_expires_at>clock_timestamp()
		AND audience=$2 AND scope @> $3::text[] FROM auth.refresh_families WHERE session_id=$1 FOR SHARE`, claims.SessionID, claims.Audience, strings.Split(claims.Scope, " ")).Scan(&valid)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !valid {
		return authjwt.ErrInvalidToken
	}
	return err
}
