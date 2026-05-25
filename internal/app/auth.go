package app

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/Inforberi/financial-intelligence/internal/core/config"
	"github.com/Inforberi/financial-intelligence/internal/core/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/core/infra/hasher"
	"github.com/Inforberi/financial-intelligence/internal/core/infra/httpserver"
	"github.com/Inforberi/financial-intelligence/internal/core/infra/logger"
	"github.com/Inforberi/financial-intelligence/internal/core/infra/postgres"
	"github.com/Inforberi/financial-intelligence/internal/core/infra/sessiontoken"
	register_postgres "github.com/Inforberi/financial-intelligence/internal/featers/register/repo/postgres"
	register_service "github.com/Inforberi/financial-intelligence/internal/featers/register/service"
	register_http "github.com/Inforberi/financial-intelligence/internal/featers/register/transport/http"
	session_postgres "github.com/Inforberi/financial-intelligence/internal/featers/session/repo/postgres"
	session_service "github.com/Inforberi/financial-intelligence/internal/featers/session/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"go.uber.org/zap"
)

func Run() error {
	// init context
	ctx := context.Background()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	// init config
	cfg, err := config.New()
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	// init logger
	log := logger.CreateLogger(cfg.Logger)
	defer func() {
		_ = log.Sync()
	}()
	undo := zap.RedirectStdLog(log)
	defer undo()

	// init argon tokenGen
	argonHash := hasher.NewArgon2idHash(1, 32, 64*1024, 32, 256)

	// init postgres
	pool, err := postgres.New(ctx, cfg.Postgres)
	if err != nil {
		return fmt.Errorf("create postgres pool: %w", err)
	}
	defer pool.Close()
	log.Info("postgres pool created successfully")

	now := clock.UTCClock{}
	tokenGen := sessiontoken.TokenManager{}

	// init session
	sessionRepo := session_postgres.New(pool)
	sessionService := session_service.New(now, sessionRepo, tokenGen, cfg.Session)

	// init register
	registerRepo := register_postgres.New(pool)
	registerService := register_service.New(argonHash, registerRepo, sessionService)

	registerLogger := log.With(zap.String("feature", "register"), zap.String("layer", "transport"))
	registerHandler := register_http.New(registerService, registerLogger)

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Get("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("pong"))
	})

	r.Post("/auth/register", registerHandler.RegisterByEmail)

	return httpserver.Run(ctx, log, cfg.Server, r)
}
