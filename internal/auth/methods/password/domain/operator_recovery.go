package domain

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

var (
	ErrOperatorRecoveryDenied   = errors.New("operator recovery denied or target unavailable")
	ErrOperatorRecoveryConflict = errors.New("operator recovery account version changed")
	ErrOperatorRecoveryInput    = errors.New("invalid operator recovery request")
	ErrOperatorPasswordPolicy   = errors.New("new password does not satisfy password policy")
)

type OperatorRecovery struct {
	UserID          accountdomain.UserID
	ExpectedVersion int64
	Environment     string
	Reason          string
}

func (r OperatorRecovery) Validate() error {
	if !accountdomain.ValidUserID(r.UserID) || r.ExpectedVersion < 1 {
		return ErrOperatorRecoveryInput
	}
	if r.Environment != "dev" && r.Environment != "test" && r.Environment != "prod" {
		return ErrOperatorRecoveryInput
	}
	if r.Reason != strings.TrimSpace(r.Reason) || len(r.Reason) == 0 || len(r.Reason) > 500 || !utf8.ValidString(r.Reason) {
		return ErrOperatorRecoveryInput
	}
	for _, c := range r.Reason {
		if unicode.IsControl(c) {
			return ErrOperatorRecoveryInput
		}
	}
	return nil
}
