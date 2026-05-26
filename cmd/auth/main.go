package main

import (
	"log"

	_ "github.com/Inforberi/financial-intelligence/docs"
	"github.com/Inforberi/financial-intelligence/internal/app"
)

// @title Auth API
// @version 1.0
// @description Financial Intelligence API
// @host localhost:8080
// @BasePath /api/v1/
// @schemes http

func main() {
	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
