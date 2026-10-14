package main

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func connectionConfig(dsn, environment string) (*pgxpool.Config, string, error) {
	if environment != "dev" && environment != "test" && environment != "prod" {
		return nil, "", errors.New("environment must be dev, test or prod")
	}
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Hostname() == "" || u.User == nil || u.Path == "" || u.Path == "/" || len(dsn) > 8192 {
		return nil, "", errors.New("AUTH_RECOVERY_DATABASE_URL must be an explicit PostgreSQL URL")
	}
	if environment == "prod" && u.Query().Get("sslmode") != "verify-full" {
		return nil, "", errors.New("production recovery requires sslmode=verify-full")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, "", errors.New("invalid operator database configuration")
	}
	if err := validateEndpoint(cfg, environment); err != nil {
		return nil, "", err
	}
	cfg.MaxConns, cfg.MinConns = 1, 0
	cfg.ConnConfig.ConnectTimeout = 5 * time.Second
	cfg.MaxConnIdleTime = time.Minute
	cfg.MaxConnLifetime = 5 * time.Minute
	return cfg, net.JoinHostPort(cfg.ConnConfig.Host, strconv.Itoa(int(cfg.ConnConfig.Port))), nil
}

func validateEndpoint(cfg *pgxpool.Config, environment string) error {
	if len(cfg.ConnConfig.Fallbacks) != 0 {
		return errors.New("operator recovery requires one endpoint without connection fallbacks")
	}
	if environment == "prod" {
		tls := cfg.ConnConfig.TLSConfig
		if tls == nil || tls.InsecureSkipVerify || tls.ServerName == "" {
			return errors.New("production recovery requires certificate and hostname verification")
		}
		return nil
	}
	ip := net.ParseIP(cfg.ConnConfig.Host)
	if cfg.ConnConfig.Host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return errors.New("dev/test recovery permits only loopback hosts; use prod with verified TLS elsewhere")
	}
	return nil
}

func connect(ctx context.Context, dsn, environment string) (*pgxpool.Pool, string, error) {
	cfg, destination, err := connectionConfig(dsn, environment)
	if err != nil {
		return nil, "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, "", errors.New("operator database connection failed")
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, "", errors.New("operator database connection failed")
	}
	return pool, destination, nil
}
