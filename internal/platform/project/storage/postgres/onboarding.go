package postgres

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

// PrepareOnboarding pins setup authority and policy, not an administrator or a ready runtime.
func (t *Target) PrepareOnboarding(ctx context.Context, proof credentials.SetupProof, authorize func(context.Context) error) error {
	initial := settingsdomain.Policy{Methods: settingsdomain.PublicMethods{Password: true}, PasswordEmailVerification: settingsdomain.VerificationDisabled}
	return t.prepareConfiguration(ctx, proof, initial, authorize)
}

// PrepareManagedConfiguration keeps public Auth closed; it creates no administrator.
func (t *Target) PrepareManagedConfiguration(ctx context.Context, proof credentials.SetupProof, authorize func(context.Context) error) error {
	initial := settingsdomain.Policy{PasswordEmailVerification: settingsdomain.VerificationDisabled}
	return t.prepareConfiguration(ctx, proof, initial, authorize)
}

func (t *Target) prepareConfiguration(ctx context.Context, proof credentials.SetupProof, initial settingsdomain.Policy, authorize func(context.Context) error) error {
	binding, err := t.SecretsBinding()
	if err != nil || proof.Binding() != binding || proof.Digest() == "" || authorize == nil {
		return domain.ErrConflict
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := t.checkOnboardingPreparation(ctx, binding); err != nil {
		return err
	}
	return t.withProjectAccess(ctx, authorize, func(check context.Context, project *pgx.Conn) error {
		// A newly opened connection is re-attested before touching Auth tables.
		if err := t.installProjectSchema(check, project, t.prepared.reservation, t.prepared.resources); err != nil {
			return err
		}
		return t.initializeOnboarding(check, project, proof, initial, authorize)
	})
}

func (t *Target) checkOnboardingPreparation(ctx context.Context, binding credentials.Binding) error {
	if err := t.CheckRuntime(ctx); err != nil {
		return err
	}
	runtime := "authr_" + strings.TrimPrefix(t.prepared.resources.Owner, "autho_")
	if err := t.checkPasswordTarget(ctx, t.conn, runtime, binding); err != nil {
		return err
	}
	var passwordInstalled bool
	err := t.conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM provisioning.resources WHERE project_id=$1
		AND reservation_id=$2 AND database_oid=$3 AND owner_oid=$4 AND runtime_oid=$5
		AND generation=$6 AND password_fingerprint IS NOT NULL AND schema_started)`,
		binding.ProjectID, binding.ReservationID, binding.DatabaseOID, binding.OwnerOID, binding.RuntimeOID, t.prepared.reservation.Generation).Scan(&passwordInstalled)
	if err != nil {
		return unavailable(ctx)
	}
	if !passwordInstalled {
		return domain.ErrConflict
	}
	return nil
}

func (t *Target) initializeOnboarding(ctx context.Context, project *pgx.Conn, proof credentials.SetupProof, initial settingsdomain.Policy, authorize func(context.Context) error) error {
	tx, err := project.Begin(ctx)
	if err != nil {
		return unavailable(ctx)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		_ = tx.Rollback(cleanup) //nolint:gosec // Settings, pinned proof and preparation marker commit together.
	}()
	owner := pgx.Identifier{t.prepared.resources.Owner}.Sanitize()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(1096111176,2); SET LOCAL ROLE `+owner); err != nil {
		return unavailable(ctx)
	}
	if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
		return unavailable(ctx)
	}
	prepared, err := t.checkOnboardingState(ctx, tx, proof)
	if err != nil {
		return err
	}
	snapshot, err := settingspostgres.InitializeInTransaction(ctx, tx, initial)
	if err != nil {
		return unavailable(ctx)
	}
	if snapshot.Version != 1 || snapshot.Policy != initial {
		return domain.ErrConflict
	}
	if err := accountpostgres.PrepareSetupInTransaction(ctx, tx, proof.Digest()); err != nil {
		if errors.Is(err, accountdomain.ErrSetupConflict) || errors.Is(err, accountdomain.ErrSetupClosed) {
			return domain.ErrConflict
		}
		return unavailable(ctx)
	}
	if !prepared {
		if _, err := tx.Exec(ctx, `UPDATE project_meta.identity SET configuration_prepared=true,setup_operator_hash=$1 WHERE singleton`, proof.Digest()); err != nil {
			return unavailable(ctx)
		}
	}
	if err := authorize(ctx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return unavailable(ctx)
	}
	return nil
}

func (t *Target) checkOnboardingState(ctx context.Context, tx pgx.Tx, proof credentials.SetupProof) (bool, error) {
	b := proof.Binding()
	var prepared bool
	var operator *string
	err := tx.QueryRow(ctx, `SELECT configuration_prepared,setup_operator_hash FROM project_meta.identity
		WHERE singleton AND realm_id=$1 AND project_id=$2 AND reservation_id=$3 AND database_oid=$4
		AND owner_oid=$5 AND runtime_oid=$6 AND schema_version=$7 FOR UPDATE`,
		b.RealmID, b.ProjectID, b.ReservationID, b.DatabaseOID, b.OwnerOID, b.RuntimeOID, b.SchemaVersion).Scan(&prepared, &operator)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, domain.ErrConflict
	}
	if err != nil {
		return false, unavailable(ctx)
	}
	if prepared && (operator == nil || *operator != proof.Digest()) {
		return false, domain.ErrConflict
	}
	var policy, setup, occupied bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.auth_settings),EXISTS(SELECT 1 FROM auth.initial_setup),
		EXISTS(SELECT 1 FROM auth.users) OR EXISTS(SELECT 1 FROM auth.roles)`).Scan(&policy, &setup, &occupied)
	if err != nil {
		return false, unavailable(ctx)
	}
	if occupied || prepared != policy || prepared != setup {
		return false, domain.ErrConflict
	}
	return prepared, nil
}
