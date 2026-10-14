package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type mfaOperator interface {
	Preview(context.Context, accountdomain.UserID, string) (*mfaservice.RecoveryTarget, error)
	Decide(context.Context, domain.RecoveryDecision) error
}

func parseMFAOptions(args []string) (domain.RecoveryDecision, error) {
	result := domain.RecoveryDecision{Approve: args[0] == "mfa-approve"}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var user string
	flags.StringVar(&user, "user", "", "existing account UUID")
	flags.StringVar(&result.RequestID, "request", "", "exact recovery request UUID")
	flags.StringVar(&result.Environment, "environment", "", "explicit environment")
	flags.StringVar(&result.Reason, "reason", "", "independent identity verification incident reference")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return result, flag.ErrHelp
		}
		return result, domain.ErrRecoveryOperatorInput
	}
	result.UserID = accountdomain.UserID(user)
	if flags.NArg() != 0 || user == "" || result.RequestID == "" || result.Environment == "" || result.Reason == "" || len(result.Reason) > 500 {
		return result, domain.ErrRecoveryOperatorInput
	}
	return result, nil
}

func runMFA(ctx context.Context, args []string) error {
	opts, err := parseMFAOptions(args)
	if errors.Is(err, flag.ErrHelp) {
		_, err = io.WriteString(os.Stdout, usage)
		return err
	}
	if err != nil {
		return err
	}
	pool, destination, err := connect(ctx, os.Getenv("AUTH_RECOVERY_DATABASE_URL"), opts.Environment)
	if err != nil {
		return err
	}
	defer pool.Close()
	svc := mfaservice.NewRecoveryOperator(mfapostgres.New(pool))
	return executeMFA(ctx, opts, destination, svc, os.Stdin, os.Stdout)
}

func executeMFA(ctx context.Context, opts domain.RecoveryDecision, destination string, svc mfaOperator, input io.Reader, output io.Writer) error {
	target, err := svc.Preview(ctx, opts.UserID, opts.RequestID)
	if err != nil {
		return publicMFAError(err)
	}
	opts.ExpectedVersion = target.AuthVersion
	action := "MFA-CANCEL"
	if opts.Approve {
		action = "MFA-APPROVE"
	}
	confirmation := fmt.Sprintf("%s %s %s/%s %s %s v%d", action, opts.Environment, destination, target.Database, opts.UserID, opts.RequestID, target.AuthVersion)
	if _, err := fmt.Fprintf(output, "Environment: %q\nDatabase: %q\nOperator: %q\nTarget: %s\nRequest: %s (%s), expires=%s\nReason: %q\nNo factor replacement or session issuance. Approval requires independent owner verification.\nType exactly:\n%s\n> ",
		opts.Environment, destination+"/"+target.Database, target.Operator, opts.UserID, opts.RequestID, target.State, target.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"), opts.Reason, confirmation); err != nil {
		return errors.New("cannot display MFA recovery confirmation")
	}
	if err := confirmRecovery(input, confirmation); err != nil {
		return err
	}
	if err := svc.Decide(ctx, opts); err != nil {
		return publicMFAError(err)
	}
	_, err = io.WriteString(output, "MFA recovery decision committed. Existing factor and sessions unchanged.\n")
	return err
}

func publicMFAError(err error) error {
	for _, known := range []error{domain.ErrRecoveryOperatorDenied, domain.ErrRecoveryOperatorInput} {
		if errors.Is(err, known) {
			return known
		}
	}
	return errors.New("MFA recovery decision failed; outcome may be unknown after connection failure; check request and audit before retry")
}
