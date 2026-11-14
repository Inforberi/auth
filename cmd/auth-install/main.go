package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("auth-install", flag.ContinueOnError)
	dir := flags.String("dir", "", "new private installation directory outside the repository")
	name := flags.String("name", "", "unique Compose project name")
	origin := flags.String("origin", "", "public HTTPS origin")
	smtpHost := flags.String("smtp-host", "", "trusted SMTP relay hostname")
	smtpFrom := flags.String("smtp-from", "", "SMTP sender address")
	smtpPort := flags.Uint("smtp-port", 587, "SMTP submission port")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *dir == "" {
		return fmt.Errorf("provide -dir and use named installation flags")
	}
	input := installation{Name: *name, Origin: *origin, SMTPHost: *smtpHost, SMTPFrom: *smtpFrom, SMTPPort: *smtpPort}
	if err := input.validate(); err != nil {
		return err
	}
	if err := writeBundle(*dir, input); err != nil {
		return err
	}
	_, err := fmt.Fprintln(output, "Installation bundle is ready. Keep a protected copy before starting Auth.")
	return err
}
