package main

import (
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

func connectionConfig(dsn string) (*pgx.ConnConfig, error) {
	u, err := url.Parse(dsn)
	if err != nil || len(dsn) > 8192 || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.User == nil || u.Path == "" || u.Path == "/" {
		return nil, errors.New("explicit PostgreSQL URL required")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || len(cfg.Fallbacks) != 0 || cfg.User == "" || cfg.Database == "" {
		return nil, errors.New("one PostgreSQL endpoint without fallbacks required")
	}
	if (u.Hostname() == "" && !strings.HasPrefix(u.Query().Get("host"), "/")) ||
		(u.Hostname() != "" && cfg.Host != u.Hostname()) || cfg.User != u.User.Username() || cfg.Database != strings.TrimPrefix(u.Path, "/") {
		return nil, errors.New("database, user and one host must be explicit in the URL")
	}
	if err := validateTransport(cfg, u); err != nil {
		return nil, err
	}
	// Runtime parameters come only from this process, not PGOPTIONS or URL overrides.
	cfg.RuntimeParams = map[string]string{
		"application_name": "auth-project-prepare", "statement_timeout": "45000", "lock_timeout": "2000", "idle_in_transaction_session_timeout": "5000",
	}
	cfg.ConnectTimeout = 5 * time.Second
	return cfg, nil
}

func validateTransport(cfg *pgx.ConnConfig, u *url.URL) error {
	if strings.HasPrefix(cfg.Host, "/") {
		if u.Query().Get("host") != cfg.Host || u.Query().Get("sslmode") != "disable" {
			return errors.New("local Unix socket must be explicit")
		}
		return nil
	}
	if u.Query().Get("sslmode") != "verify-full" || cfg.TLSConfig == nil || cfg.TLSConfig.InsecureSkipVerify || cfg.TLSConfig.ServerName == "" {
		return errors.New("network connections require sslmode=verify-full")
	}
	return nil
}
