package domain

import (
	"errors"
	"strings"
	"testing"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func TestRecoveryDecisionValidation(t *testing.T) {
	valid := RecoveryDecision{UserID: accountdomain.UserID("11111111-1111-4111-8111-111111111111"), RequestID: "22222222-2222-4222-8222-222222222222", ExpectedVersion: 2, Environment: "test", Reason: "INC-42", Approve: true}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, reason := range []string{"", " padded", "two\nlines", strings.Repeat("x", 501), string([]byte{0xff})} {
		bad := valid
		bad.Reason = reason
		if err := bad.Validate(); !errors.Is(err, ErrRecoveryOperatorInput) {
			t.Fatal("invalid reason", err)
		}
	}
	for _, change := range []func(*RecoveryDecision){
		func(r *RecoveryDecision) { r.ExpectedVersion = 0 },
		func(r *RecoveryDecision) { r.RequestID = "invalid" },
		func(r *RecoveryDecision) { r.UserID = "invalid" },
		func(r *RecoveryDecision) { r.Environment = "unknown" },
	} {
		bad := valid
		change(&bad)
		if err := bad.Validate(); !errors.Is(err, ErrRecoveryOperatorInput) {
			t.Fatal("invalid target", err)
		}
	}
}
