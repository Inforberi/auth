package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func New(ctx context.Context, cfg Config) (*pgxpool.Pool, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("postgres url is required")
	}

	config, err := pgxpool.ParseConfig(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid PostgreSQL configuration")
	}

	config.MaxConns = int32(cfg.MaxConns)
	config.MinConns = int32(cfg.MinConns)
	config.MaxConnLifetime = cfg.MaxConnLifetime
	config.MaxConnIdleTime = cfg.MaxConnIdleTime

	connectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	config.ConnConfig.ConnectTimeout = 5 * time.Second
	pool, err := pgxpool.NewWithConfig(connectCtx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create PostgreSQL pool")
	}

	if err := pool.Ping(connectCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to connect to PostgreSQL")
	}

	return pool, nil
}
