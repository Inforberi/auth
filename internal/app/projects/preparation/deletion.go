package preparation

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	storage "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/database/postgres"
	preparationpg "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/repository/postgres"
	service "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/service"
)

func runDeletion(ctx context.Context, input service.Input, connections Connections, repo *preparationpg.PreparationRepository, operation domain.ID) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, connections.Storage)
	if err != nil {
		return errors.New("storage connection failed")
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		_ = conn.Close(cleanup) //nolint:gosec // Release the exclusive target lock.
	}()
	physical, err := storage.New(conn, input.Realm, input.Target)
	if err != nil {
		return err
	}
	if err := physical.CheckRuntime(ctx); err != nil {
		return err
	}
	if err := physical.Lock(ctx); err != nil {
		return err
	}
	target, err := repo.DeletionTarget(ctx, operation, connections.Codec)
	if err != nil {
		return err
	}
	if target.Stage != "confirmed" && target.Stage != "draining" && target.Stage != "verified" {
		return nil
	}
	if target.Expired && target.Stage == "confirmed" {
		return repo.AdvanceDeletion(ctx, operation, "confirmed", "expired")
	}
	seal := func(ctx context.Context) error {
		if target.Stage == "draining" {
			return nil
		}
		return repo.AdvanceDeletion(ctx, operation, "confirmed", "draining")
	}
	certify := func(ctx context.Context) error { return repo.AdvanceDeletion(ctx, operation, "draining", "verified") }
	if err := physical.DeleteConfirmed(ctx, target.Binding, target.Credential.Password(), target.AcknowledgeUsers, target.Stage == "draining", target.Stage == "verified", target.Expired, seal, certify); err != nil {
		if errors.Is(err, storage.ErrDeletionHasUsers) {
			return repo.AdvanceDeletion(ctx, operation, "draining", "users_present")
		}
		return err
	}
	if target.Expired {
		return repo.AdvanceDeletion(ctx, operation, "draining", "expired")
	}
	return repo.AdvanceDeletion(ctx, operation, "verified", "deleted")
}
