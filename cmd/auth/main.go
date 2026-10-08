package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/Inforberi/financial-intelligence/docs"
	authapp "github.com/Inforberi/financial-intelligence/internal/app/auth"
	"github.com/Inforberi/financial-intelligence/internal/config"
)

// @title Auth API
// @version 1.0
// @description Reusable authentication service. Cookie sessions require HTTPS. CSRF protection is a later release prerequisite.
// @BasePath /
// @schemes https http

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cfg, err := config.New()
	if err != nil {
		return err
	}
	app, err := authapp.New(ctx, cfg)
	if err != nil {
		return err
	}
	return app.Run(ctx)
}
