package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
)

type recovery interface {
	Preview(context.Context, accountdomain.UserID) (*passwordservice.OperatorRecoveryTarget, error)
	Reset(context.Context, passworddomain.OperatorRecovery, []byte) (int64, error)
}

func execute(ctx context.Context, opts options, destination string, svc recovery, input io.Reader, output io.Writer, passwordInput func() ([]byte, error)) error {
	target, err := svc.Preview(ctx, opts.user)
	if err != nil {
		return publicError(err)
	}
	request := passworddomain.OperatorRecovery{UserID: opts.user, ExpectedVersion: target.AuthVersion, Environment: opts.environment, Reason: opts.reason}
	confirmation := fmt.Sprintf("RESET %s %s/%s %s v%d", opts.environment, destination, target.Database, opts.user, target.AuthVersion)
	if _, err := fmt.Fprintf(output, "Environment: %q\nDatabase: %q\nOperator: %q\nTarget: %s (%s), auth_version=%d\nReason: %q\nRoles, MFA, contact and account status will not change.\nType exactly:\n%s\n> ", opts.environment, destination+"/"+target.Database, target.Operator, opts.user, target.Status, target.AuthVersion, opts.reason, confirmation); err != nil {
		return errors.New("cannot display recovery confirmation")
	}
	line, err := bufio.NewReader(io.LimitReader(input, 512)).ReadString('\n')
	if (err != nil && !errors.Is(err, io.EOF)) || strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r") != confirmation {
		return errors.New("recovery cancelled: confirmation mismatch")
	}
	password, err := passwordInput()
	if err != nil {
		return errors.New("cannot read new password from pipe descriptor 3")
	}
	defer clear(password)
	version, err := svc.Reset(ctx, request, password)
	if err != nil {
		return publicError(err)
	}
	_, err = fmt.Fprintf(output, "Password reset committed; auth_version=%d. Old sessions revoked. Sign in normally with MFA.\n", version)
	return err
}

func publicError(err error) error {
	for _, known := range []error{passworddomain.ErrOperatorRecoveryDenied, passworddomain.ErrOperatorRecoveryConflict, passworddomain.ErrOperatorRecoveryInput, passworddomain.ErrOperatorPasswordPolicy} {
		if errors.Is(err, known) {
			return known
		}
	}
	return errors.New("recovery failed; no details or secrets logged; outcome may be unknown after a connection failure, check version and audit before retry")
}
