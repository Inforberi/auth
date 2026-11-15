package preparation

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	preparationpg "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/repository/postgres"
	service "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/service"
)

func Watch(ctx context.Context, input service.Input, connections Connections) (service.Result, error) {
	cfg, err := pgxpool.ParseConfig(connections.Catalog.ConnString())
	if err != nil {
		return service.Result{}, errors.New("catalog configuration failed")
	}
	cfg.ConnConfig = connections.Catalog.Copy()
	cfg.MaxConns, cfg.MinConns = 1, 0
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return service.Result{}, errors.New("catalog connection failed")
	}
	defer pool.Close()
	repo, err := preparationpg.NewPreparation(pool, input.Realm, input.Target)
	if err != nil {
		return service.Result{}, err
	}
	if err := repo.CheckRuntime(ctx); err != nil {
		return service.Result{}, err
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	input.Watch = false
	for ctx.Err() == nil {
		check, cancel := context.WithTimeout(ctx, 3*time.Second)
		operation, err := repo.NextRequested(check)
		cancel()
		switch {
		case err == nil:
			input.Request.OperationID = operation
			if _, err := Run(ctx, input, connections); err != nil && ctx.Err() == nil {
				log.Printf("project preparation %s needs a retry", operation)
			}
		case !errors.Is(err, domain.ErrNotFound) && ctx.Err() == nil:
			log.Print("project preparation queue unavailable")
		}
		check, cancel = context.WithTimeout(ctx, 3*time.Second)
		deletion, err := repo.NextDeletion(check)
		cancel()
		if err == nil {
			if err := runDeletion(ctx, input, connections, repo, deletion); err != nil && ctx.Err() == nil {
				log.Printf("project deletion %s needs a retry", deletion)
			}
		} else if !errors.Is(err, domain.ErrNotFound) && ctx.Err() == nil {
			log.Print("project deletion queue unavailable")
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
	return service.Result{Stage: "stopped"}, nil
}
