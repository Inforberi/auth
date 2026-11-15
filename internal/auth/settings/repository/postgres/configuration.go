package postgres

import (
	"bytes"
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	configuration "github.com/Inforberi/financial-intelligence/internal/auth/settings/configuration/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

const configurationLock int64 = 734013982

func (r *Repository) StartConfiguration(ctx context.Context, input configuration.Prepared) (configuration.Lease, error) {
	conn, err := r.db.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	lease := &configurationLease{conn: conn}
	accepted := false
	defer func() {
		if !accepted {
			lease.close(ctx)
		}
	}()
	var locked bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock_shared($1)`, configurationLock).Scan(&locked); err != nil {
		return nil, err
	}
	if !locked {
		return nil, domain.ErrSourceConflict
	}
	var mode domain.SourceMode
	var initialized bool
	var fingerprint, keyBinding []byte
	if err := conn.QueryRow(ctx, `SELECT mode,initialized,fingerprint,key_binding FROM auth.settings_source WHERE singleton`).Scan(&mode, &initialized, &fingerprint, &keyBinding); err != nil {
		return nil, err
	}
	if initialized && mode != input.Mode {
		return nil, domain.ErrSourceConflict
	}
	if initialized && mode == domain.SourceENV && !bytes.Equal(keyBinding, input.KeyBinding) {
		return nil, domain.ErrSourceConflict
	}
	changed := !initialized || input.Mode == domain.SourceENV && !bytes.Equal(fingerprint, input.Fingerprint)
	if changed && input.Mode == domain.SourceAPI {
		if err := r.commitConfiguration(ctx, conn, input); err != nil {
			return nil, err
		}
	} else if changed {
		if err := r.replaceEnvironment(ctx, conn, input); err != nil {
			return nil, err
		}
	}
	if err := checkEnvironmentSettings(ctx, conn, input.Mode); err != nil {
		return nil, err
	}
	accepted = true
	return lease, nil
}

func checkEnvironmentSettings(ctx context.Context, conn *pgxpool.Conn, mode domain.SourceMode) error {
	if mode == domain.SourceENV {
		var complete bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.auth_settings) AND EXISTS(SELECT 1 FROM auth.smtp_settings) AND EXISTS(SELECT 1 FROM auth.retention_settings) AND (SELECT count(*)=2 FROM auth.provider_settings)`).Scan(&complete); err != nil {
			return err
		}
		if !complete {
			return domain.ErrNotInitialized
		}
	}
	return nil
}

func (r *Repository) replaceEnvironment(ctx context.Context, conn *pgxpool.Conn, input configuration.Prepared) error {
	var locked bool
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_unlock_shared($1)`, configurationLock); err != nil {
		return err
	}
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, configurationLock).Scan(&locked); err != nil {
		return err
	}
	if !locked {
		return domain.ErrSourceConflict
	}
	if err := r.commitConfiguration(ctx, conn, input); err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock_shared($1)`, configurationLock); err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, configurationLock); err != nil {
		return err
	}
	return nil
}

func (r *Repository) commitConfiguration(ctx context.Context, conn *pgxpool.Conn, input configuration.Prepared) error {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup) //nolint:gosec // Commit owns success; preserve the original error.
	}()
	if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
		return err
	}
	var mode domain.SourceMode
	var initialized bool
	var generation int64
	if err := tx.QueryRow(ctx, `SELECT mode,initialized,generation FROM auth.settings_source WHERE singleton FOR UPDATE`).Scan(&mode, &initialized, &generation); err != nil {
		return err
	}
	if initialized && mode != input.Mode {
		return domain.ErrSourceConflict
	}
	if initialized && input.Mode == domain.SourceAPI {
		return tx.Commit(ctx)
	}
	if input.Mode == domain.SourceENV {
		if !initialized {
			var existing bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.auth_settings) OR EXISTS(SELECT 1 FROM auth.initial_setup WHERE initialized_at IS NOT NULL)`).Scan(&existing); err != nil {
				return err
			}
			if existing {
				return domain.ErrSourceAdoption
			}
		}
		var previous map[string]string
		if err := tx.QueryRow(ctx, `SELECT component_hashes FROM auth.settings_source WHERE singleton`).Scan(&previous); err != nil {
			return err
		}
		if err := r.synchronizeEnvironment(ctx, tx, input, previous, initialized); err != nil {
			return err
		}
	}
	event := "initialize"
	if initialized {
		event = "synchronize"
		generation++
	}
	if _, err := tx.Exec(ctx, `UPDATE auth.settings_source SET mode=$1,initialized=true,generation=$2,fingerprint=$3,component_hashes=$4,key_binding=$5 WHERE singleton`, input.Mode, generation, input.Fingerprint, input.ComponentHashes, input.KeyBinding); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO auth.settings_source_audit(generation,mode,event) VALUES($1,$2,$3)`, generation, input.Mode, event); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Caller has already established current actor authority and holds Access locks.
func RequireAPISettings(ctx context.Context, tx pgx.Tx) error {
	return requireAPISettings(ctx, tx, `SELECT mode FROM auth.settings_source WHERE singleton FOR SHARE`)
}

// CheckAPISettings verifies the source before external I/O in a read-only transaction.
func CheckAPISettings(ctx context.Context, tx pgx.Tx) error {
	return requireAPISettings(ctx, tx, `SELECT mode FROM auth.settings_source WHERE singleton`)
}

func requireAPISettings(ctx context.Context, tx pgx.Tx, query string) error {
	if configuration.EnvironmentOwned(ctx) {
		return domain.ErrSourceReadOnly
	}
	var mode domain.SourceMode
	if err := tx.QueryRow(ctx, query).Scan(&mode); err != nil {
		return err
	}
	if mode != domain.SourceAPI {
		return domain.ErrSourceReadOnly
	}
	return nil
}
