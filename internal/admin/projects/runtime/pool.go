package runtime

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

func (p projectPool) sqlPool() *pgxpool.Pool { return p.Pool }

// UsePool borrows the existing pool without pinning a connection during CPU work.
// The callback must not close/retain it, spawn work or nest registry acquisitions.
// Its logical lease holds one MaxAcquiring slot through callback completion.
func (r *Registry) UsePool(ctx context.Context, key Key, use func(context.Context, *pgxpool.Pool) error) error {
	if r == nil || !key.Valid() || use == nil {
		return ErrUnavailable
	}
	select {
	case r.acquires <- struct{}{}:
	default:
		return ErrBusy
	}
	defer func() { <-r.acquires }()
	acquireCtx, cancel := context.WithTimeout(ctx, r.config.AcquireTimeout)
	entry, err := r.borrow(acquireCtx, key)
	cancel()
	if err != nil {
		return err
	}
	defer r.release(entry)
	source, ok := entry.pool.(interface{ sqlPool() *pgxpool.Pool })
	if !ok {
		return ErrUnavailable
	}
	pool := source.sqlPool()
	if pool == nil {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return use(ctx, pool)
}
