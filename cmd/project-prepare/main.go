package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	preparationcli "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/transport/cli"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := preparationcli.Run(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr, runPreparation)
	cancel()
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
