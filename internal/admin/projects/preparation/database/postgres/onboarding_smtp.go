package postgres

import (
	"context"
	"crypto/subtle"
	"time"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingssmtp "github.com/Inforberi/financial-intelligence/internal/auth/settings/smtp/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type OnboardingSMTP struct {
	Config         settingsdomain.SMTPConfig
	Password       string `json:"-"`
	AllowedTargets []string
}

func (OnboardingSMTP) String() string     { return "[REDACTED onboarding SMTP]" }
func (s OnboardingSMTP) GoString() string { return s.String() }
func (OnboardingSMTP) MarshalJSON() ([]byte, error) {
	return []byte(`"[REDACTED onboarding SMTP]"`), nil
}

// PrepareSMTP accepts trusted configuration, never imports platform SMTP or contacts a mail server.
func (t *Target) PrepareSMTP(ctx context.Context, keys credentials.OnboardingKeys, input OnboardingSMTP, authorize func(context.Context) error) (settingsdomain.SMTPSnapshot, error) {
	binding, err := t.SecretsBinding()
	if err != nil || keys.Binding() != binding || keys.EncryptionKey() == "" || keys.Proof().Digest() == "" || authorize == nil {
		return settingsdomain.SMTPSnapshot{}, domain.ErrConflict
	}
	scope, err := realmscope.New("project", string(binding.ProjectID))
	if err != nil {
		return settingsdomain.SMTPSnapshot{}, err
	}
	purpose, err := scope.Purpose("smtp-settings:v1")
	if err != nil {
		return settingsdomain.SMTPSnapshot{}, err
	}
	cipher, err := secretbox.NewScoped(keys.EncryptionKey(), purpose)
	if err != nil {
		return settingsdomain.SMTPSnapshot{}, domain.ErrConflict
	}
	seed, err := settingssmtp.NewSMTPSeed(input.Config, input.Password, input.AllowedTargets, true, cipher)
	if err != nil {
		return settingsdomain.SMTPSnapshot{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := t.checkOnboardingPreparation(ctx, binding); err != nil {
		return settingsdomain.SMTPSnapshot{}, err
	}
	var result settingsdomain.SMTPSnapshot
	err = t.withProjectAccess(ctx, authorize, func(check context.Context, project *pgx.Conn) error {
		if err := t.installProjectSchema(check, project, t.prepared.reservation, t.prepared.resources); err != nil {
			return err
		}
		var err error
		result, err = t.initializeSMTP(check, project, keys.Proof(), seed, input.Password, cipher, authorize)
		return err
	})
	if err != nil {
		return settingsdomain.SMTPSnapshot{}, err
	}
	return result, nil
}

func (t *Target) initializeSMTP(ctx context.Context, project *pgx.Conn, proof credentials.SetupProof, seed settingssmtp.SMTPStored, password string, cipher *secretbox.Cipher, authorize func(context.Context) error) (settingsdomain.SMTPSnapshot, error) {
	tx, err := project.Begin(ctx)
	if err != nil {
		return settingsdomain.SMTPSnapshot{}, unavailable(ctx)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		_ = tx.Rollback(cleanup) //nolint:gosec // SMTP and its retained receipt commit together.
	}()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(1096111176,2); SET LOCAL ROLE `+pgx.Identifier{t.prepared.resources.Owner}.Sanitize()); err != nil {
		return settingsdomain.SMTPSnapshot{}, unavailable(ctx)
	}
	if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
		return settingsdomain.SMTPSnapshot{}, unavailable(ctx)
	}
	prepared, err := t.checkOnboardingState(ctx, tx, proof)
	if err != nil {
		return settingsdomain.SMTPSnapshot{}, err
	}
	if !prepared {
		return settingsdomain.SMTPSnapshot{}, domain.ErrConflict
	}
	var recorded, present bool
	err = tx.QueryRow(ctx, `SELECT smtp_prepared,EXISTS(SELECT 1 FROM auth.smtp_settings) FROM project_meta.identity WHERE singleton`).Scan(&recorded, &present)
	if err != nil {
		return settingsdomain.SMTPSnapshot{}, unavailable(ctx)
	}
	if recorded != present {
		return settingsdomain.SMTPSnapshot{}, domain.ErrConflict
	}
	stored, err := settingspostgres.InitializeSMTPInTransaction(ctx, tx, seed)
	if err != nil {
		return settingsdomain.SMTPSnapshot{}, unavailable(ctx)
	}
	plain, err := cipher.Open(stored.Password)
	if err != nil {
		return settingsdomain.SMTPSnapshot{}, domain.ErrConflict
	}
	defer clear(plain)
	if stored.Version != 1 || stored.Config != seed.Config || stored.PasswordSet != seed.PasswordSet || subtle.ConstantTimeCompare(plain, []byte(password)) != 1 {
		return settingsdomain.SMTPSnapshot{}, domain.ErrConflict
	}
	if !recorded {
		if _, err := tx.Exec(ctx, `UPDATE project_meta.identity SET smtp_prepared=true WHERE singleton`); err != nil {
			return settingsdomain.SMTPSnapshot{}, unavailable(ctx)
		}
	}
	if err := authorize(ctx); err != nil {
		return settingsdomain.SMTPSnapshot{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return settingsdomain.SMTPSnapshot{}, unavailable(ctx)
	}
	return stored.SMTPSnapshot, nil
}
