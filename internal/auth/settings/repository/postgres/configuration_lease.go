package postgres

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type configurationLease struct {
	conn *pgxpool.Conn
	mu   sync.Mutex
}

func (l *configurationLease) Close() { l.close(context.Background()) }

func (l *configurationLease) close(ctx context.Context) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	// Closing the physical session releases both shared and exclusive advisory locks.
	_ = l.conn.Hijack().Close(ctx) //nolint:gosec // A broken connection must never return to the pool with session locks.
	l.conn = nil
}

func (l *configurationLease) Check(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn == nil {
		return domain.ErrSourceConflict
	}
	return l.conn.Conn().Ping(ctx)
}
