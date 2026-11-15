package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/Inforberi/financial-intelligence/docs/api/generated"
	app "github.com/Inforberi/financial-intelligence/internal/app"
	"github.com/Inforberi/financial-intelligence/internal/config"
)

// @title Auth API
// @version 1.0
// @description Reusable authentication service. Cookie sessions require HTTPS. All auth mutations require an exact allowed Origin. CORS is opt-in; cookie profile is same-site.
// @BasePath /
// @schemes https http
// @securityDefinitions.apikey SessionCookie
// @in header
// @name Cookie
// @description Browser session cookie (__Host-session). Browser clients use credentials: include. Server clients use a cookie jar.
// @securityDefinitions.basic ServiceBasic
// @description Dedicated client credentials for token introspection.
// @securityDefinitions.apikey SetupToken
// @in header
// @name X-Setup-Token

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
	app, err := app.New(ctx, cfg)
	if err != nil {
		return err
	}
	return app.Run(ctx)
}
