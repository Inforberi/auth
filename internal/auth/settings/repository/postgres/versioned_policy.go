package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type policyTable struct {
	policy string
	audit  string
}

var (
	emailOTPPolicyTable           = policyTable{policy: "auth.email_otp_policy", audit: "auth.email_otp_policy_audit"}
	browserSessionPolicyTable     = policyTable{policy: "auth.browser_session_policy", audit: "auth.browser_session_policy_audit"}
	linkLifetimePolicyTable       = policyTable{policy: "auth.link_lifetime_policy", audit: "auth.link_lifetime_policy_audit"}
	credentialLifetimePolicyTable = policyTable{policy: "auth.credential_lifetime_policy", audit: "auth.credential_lifetime_policy_audit"}
	loginBudgetPolicyTable        = policyTable{policy: "auth.login_budget_policy", audit: "auth.login_budget_policy_audit"}
	operationBudgetsPolicyTable   = policyTable{policy: "auth.operation_budgets_policy", audit: "auth.operation_budgets_policy_audit"}
	frontendPolicyTable           = policyTable{policy: "auth.frontend_policy", audit: "auth.frontend_policy_audit"}
)

type PolicySnapshot[P comparable] struct {
	Version int64 `json:"version"`
	Policy  P     `json:"policy"`
}

type VersionedPolicy[P comparable] struct {
	repo  *Repository
	table policyTable
}

func (p VersionedPolicy[P]) Initialize(ctx context.Context, seed P) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err := p.repo.db.Exec(ctx, `UPDATE `+p.table.policy+` SET policy=$1 WHERE singleton AND policy IS NULL`, seed)
	return err
}

type policyReader interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func loadPolicy[P comparable](ctx context.Context, db policyReader, table policyTable) (P, error) {
	var policy P
	err := db.QueryRow(ctx, `SELECT policy FROM `+table.policy+` WHERE singleton AND policy IS NOT NULL`).Scan(&policy)
	return policy, err
}

func (p VersionedPolicy[P]) Load(ctx context.Context) (P, error) {
	return loadPolicy[P](ctx, p.repo.db, p.table)
}

func (p VersionedPolicy[P]) Read(ctx context.Context, actor accessservice.Principal) (PolicySnapshot[P], error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var snapshot PolicySnapshot[P]
	err := p.repo.db.QueryRow(ctx, `SELECT version,policy FROM `+p.table.policy+` WHERE singleton AND `+settingsReadGuard,
		actor.UserID, actor.TokenHash, settings.AuthSettingsManage).Scan(&snapshot.Version, &snapshot.Policy)
	if errors.Is(err, pgx.ErrNoRows) {
		return snapshot, accessdomain.ErrForbidden
	}
	return snapshot, err
}

func (p VersionedPolicy[P]) ReadProject(ctx context.Context, tx pgx.Tx, baseline P) (PolicySnapshot[P], domain.SourceMode, error) {
	var snapshot PolicySnapshot[P]
	var stored *P
	var mode domain.SourceMode
	err := tx.QueryRow(ctx, `SELECT p.version,p.policy,s.mode FROM `+p.table.policy+` p
		CROSS JOIN auth.settings_source s WHERE p.singleton AND s.singleton`).Scan(&snapshot.Version, &stored, &mode)
	snapshot.Policy = baseline
	if mode == domain.SourceAPI && stored != nil {
		snapshot.Policy = *stored
	}
	return snapshot, mode, err
}

func (p VersionedPolicy[P]) ApplyProject(ctx context.Context, tx pgx.Tx, actor accountdomain.UserID, expected int64, baseline, policy P) (PolicySnapshot[P], error) {
	if err := RequireAPISettings(ctx, tx); err != nil {
		return PolicySnapshot[P]{}, err
	}
	var result PolicySnapshot[P]
	var stored *P
	if err := tx.QueryRow(ctx, `SELECT version,policy FROM `+p.table.policy+` WHERE singleton FOR UPDATE`).Scan(&result.Version, &stored); err != nil {
		return result, err
	}
	if result.Version != expected {
		return result, domain.ErrPolicyConflict
	}
	before := baseline
	if stored != nil {
		before = *stored
	}
	result.Policy = policy
	if stored != nil && before == policy {
		return result, nil
	}
	if err := tx.QueryRow(ctx, `UPDATE `+p.table.policy+` SET policy=$1,version=version+1 WHERE singleton RETURNING version`, policy).Scan(&result.Version); err != nil {
		return result, err
	}
	_, err := tx.Exec(ctx, `INSERT INTO `+p.table.audit+`(actor_id,version,previous_policy,next_policy) VALUES($1,$2,$3,$4)`, actor, result.Version, before, policy)
	return result, err
}

func (p VersionedPolicy[P]) Update(ctx context.Context, actor accessservice.Principal, expected int64, policy P) (PolicySnapshot[P], error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var result PolicySnapshot[P]
	err := p.repo.transaction(ctx, func(tx pgx.Tx) error {
		if _, err := accesspostgres.AuthorizeMutation(ctx, tx, actor, "", settings.AuthSettingsManage); err != nil {
			return err
		}
		if err := RequireAPISettings(ctx, tx); err != nil {
			return err
		}
		var before PolicySnapshot[P]
		if err := tx.QueryRow(ctx, `SELECT version,policy FROM `+p.table.policy+` WHERE singleton FOR UPDATE`).Scan(&before.Version, &before.Policy); err != nil {
			return err
		}
		if before.Version != expected {
			return domain.ErrPolicyConflict
		}
		result = before
		if before.Policy == policy {
			return nil
		}
		if err := tx.QueryRow(ctx, `UPDATE `+p.table.policy+` SET policy=$1,version=version+1 WHERE singleton RETURNING version`, policy).Scan(&result.Version); err != nil {
			return err
		}
		result.Policy = policy
		_, err := tx.Exec(ctx, `INSERT INTO `+p.table.audit+`(actor_id,version,previous_policy,next_policy) VALUES ($1,$2,$3,$4)`, actor.UserID, result.Version, before.Policy, policy)
		return err
	})
	return result, err
}
