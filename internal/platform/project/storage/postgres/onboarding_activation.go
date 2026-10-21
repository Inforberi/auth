package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	catalog "github.com/Inforberi/financial-intelligence/internal/platform/project/repository/postgres"
)

// ActivateOnboarding enables project SQL for the setup-only HTTP profile, never marks ready.
// The SQL role retains its Auth grants; callers must not publish the normal Auth router.
// Both connections must come from trusted target configuration, not request-supplied DSNs.
func (t *Target) ActivateOnboarding(ctx context.Context, r domain.PreparationReservation, b credentials.Binding, codec *credentials.Codec, admission *catalog.PreparationRepository, runtime *pgxpool.Pool) (err error) {
	if admission == nil || codec == nil || runtime == nil {
		return domain.ErrConflict
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := t.lockOnboarding(ctx, r, b); err != nil {
		return err
	}
	if err := admission.WithdrawOnboarding(ctx, r, b); err != nil {
		return err
	}
	// Install cleanup before the first ambiguous target write. A lost reply is recovered from SQL.
	defer func() {
		if err == nil {
			return
		}
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		err = errors.Join(err, t.CloseOnboarding(cleanup, r, b, admission))
	}()
	if _, err := admission.ReadSetupProof(ctx, r, b, codec); err != nil {
		return err
	}
	authorize := func(check context.Context) error { return admission.CheckCurrent(check, r) }
	if err := t.beginOnboarding(ctx, authorize); err != nil {
		return err
	}
	if err := t.openOnboarding(ctx, authorize); err != nil {
		return err
	}
	// A fresh pool forces real authentication even if the caller's pool contains old sessions.
	cfg := runtime.Config()
	cfg.MaxConns, cfg.MinConns, cfg.MinIdleConns = 1, 0, 0
	probe, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return unavailable(ctx)
	}
	defer probe.Close()
	if err := admission.PermitOnboarding(ctx, r, b, codec, probe); err != nil {
		return err
	}
	return authorize(ctx)
}
