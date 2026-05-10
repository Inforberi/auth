package main

import (
	"fmt"
	"os"

	"github.com/Inforberi/financial-intelligence/internal/app"
)

func main() {
	if err := app.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "application failed: %v\n", err)
		os.Exit(1)
	}
}
