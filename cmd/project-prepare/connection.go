package main

import (
	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/infra/postgres"
)

func connectionConfig(dsn string) (*pgx.ConnConfig, error) {
	cfg, err := postgres.TrustedConfig(dsn)
	if err != nil {
		return nil, err
	}
	// Runtime parameters come only from this process, not PGOPTIONS or URL overrides.
	cfg.RuntimeParams = map[string]string{
		"application_name": "auth-project-prepare", "statement_timeout": "45000", "lock_timeout": "2000", "idle_in_transaction_session_timeout": "5000",
	}
	return cfg, nil
}
