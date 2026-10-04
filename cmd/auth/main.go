package main

import (
	"log"

	_ "github.com/Inforberi/financial-intelligence/docs"
	"github.com/Inforberi/financial-intelligence/internal/app"
)

// @title Auth API
// @version 1.0
// @description Reusable authentication service. Cookie sessions require HTTPS. CSRF protection is a later release prerequisite.
// @BasePath /
// @schemes https http

func main() {
	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
