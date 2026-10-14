package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	passwordpostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/postgres"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
)

type options struct {
	environment string
	user        accountdomain.UserID
	reason      string
}

const usage = "admin-recovery -environment <dev|test|prod> -user <UUID> -reason <incident reference>\nAUTH_RECOVERY_DATABASE_URL: dedicated operator connection. New password: pipe on descriptor 3.\n"

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseOptions(args []string) (options, error) {
	var result options
	flags := flag.NewFlagSet("admin-recovery", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&result.environment, "environment", "", "explicit environment")
	user := flags.String("user", "", "existing super-admin UUID")
	flags.StringVar(&result.reason, "reason", "", "incident reference, never secrets")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return result, flag.ErrHelp
		}
		return result, errors.New("invalid arguments; use admin-recovery -help")
	}
	result.user = accountdomain.UserID(*user)
	if flags.NArg() != 0 || result.environment == "" || result.user == "" || result.reason == "" {
		return result, errors.New("environment, user and reason are required; use admin-recovery -help")
	}
	return result, nil
}

func run(ctx context.Context, args []string) error {
	opts, err := parseOptions(args)
	if errors.Is(err, flag.ErrHelp) {
		_, err = io.WriteString(os.Stdout, usage)
		return err
	}
	if err != nil {
		return err
	}
	pool, destination, err := connect(ctx, os.Getenv("AUTH_RECOVERY_DATABASE_URL"), opts.environment)
	if err != nil {
		return err
	}
	defer pool.Close()
	hash := hasher.NewBounded(hasher.NewArgon2idHash(3, 32, 64*1024, 4, 32), 1)
	svc := passwordservice.NewOperatorRecovery(passwordpostgres.New(pool), hash)
	return execute(ctx, opts, destination, svc, os.Stdin, os.Stdout, readPasswordPipe)
}
