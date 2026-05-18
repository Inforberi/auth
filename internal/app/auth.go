package app

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/password/argon2id"

	"github.com/Inforberi/financial-intelligence/internal/infra/logger"
	"github.com/Inforberi/financial-intelligence/internal/infra/postgres"
	"go.uber.org/zap"
)

func Run() error {
	ctx := context.Background()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.New()
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	log := logger.CreateLogger(cfg.Logger)
	defer func() {
		_ = log.Sync()
	}()
	undo := zap.RedirectStdLog(log)
	defer undo()

	_ = argon2id.NewArgon2idHash(1, 32, 64*1024, 32, 256)

	pool, err := postgres.New(ctx, cfg.Postgres)
	if err != nil {
		return fmt.Errorf("create postgres pool: %w", err)
	}
	defer pool.Close()
	log.Info("postgres pool created successfully")

	return nil

}
