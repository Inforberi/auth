package domain

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

var (
	ErrRecoveryOperatorDenied = errors.New("MFA recovery operator denied or request unavailable")
	ErrRecoveryOperatorInput  = errors.New("invalid MFA recovery operator request")
)

type RecoveryDecision struct {
	UserID          accountdomain.UserID
	RequestID       string
	ExpectedVersion int64
	Environment     string
	Reason          string
	Approve         bool
}

func (r RecoveryDecision) Validate() error {
	if !accountdomain.ValidUserID(r.UserID) || !accountdomain.ValidUserID(accountdomain.UserID(r.RequestID)) || r.ExpectedVersion < 1 {
		return ErrRecoveryOperatorInput
	}
	if r.Environment != "dev" && r.Environment != "test" && r.Environment != "prod" {
		return ErrRecoveryOperatorInput
	}
	if r.Reason != strings.TrimSpace(r.Reason) || len(r.Reason) == 0 || len(r.Reason) > 500 || !utf8.ValidString(r.Reason) {
		return ErrRecoveryOperatorInput
	}
	for _, c := range r.Reason {
		if unicode.IsControl(c) {
			return ErrRecoveryOperatorInput
		}
	}
	return nil
}
