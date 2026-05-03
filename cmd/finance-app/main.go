package main

import (
	"context"
	"log"

	"github.com/Inforberi/financial-intelligence/internal/infra/postgres"
)

func main() {
	ctx := context.Background()

	cfg, err := newConfig()
	if err != nil {
		log.Fatalf("failed to read config: %v", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	_, err = postgres.New(ctx, cfg.Postgres)
	if err != nil {
		log.Fatalf("failed to create postgres pool: %v", err)
	}

	log.Println("postgres pool created successfully")
}
