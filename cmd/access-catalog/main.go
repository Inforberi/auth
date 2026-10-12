package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"os"

	"github.com/Inforberi/financial-intelligence/internal/access/settings"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		log.Fatal(err)
	}
}

func run(args []string, output, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("access-catalog", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	file := flags.String("file", "", "candidate JSON catalog")
	current := flags.String("current", "", "current JSON catalog; omitted means built-in permissions only")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *file == "" || flags.NArg() != 0 {
		return errors.New("use -file <candidate.json> and optional -current <current.json>")
	}
	previous, err := settings.LoadFile(*current)
	if err != nil {
		return err
	}
	candidate, err := settings.LoadFile(*file)
	if err != nil {
		return err
	}
	changes, err := settings.Preview(previous, candidate)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(changes)
}
