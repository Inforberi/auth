package domain

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPolicyEmailDeliveryRequirement(t *testing.T) {
	for _, tc := range []struct {
		name     string
		policy   Policy
		required bool
	}{
		{"closed", Policy{}, false},
		{"dormant verification", Policy{PasswordEmailVerification: VerificationRequired}, false},
		{"password only", Policy{Methods: PublicMethods{Password: true}, PasswordEmailVerification: VerificationDisabled}, false},
		{"optional verification", Policy{Methods: PublicMethods{Password: true}, PasswordEmailVerification: VerificationOptional}, true},
		{"required verification", Policy{Methods: PublicMethods{Password: true}, PasswordEmailVerification: VerificationRequired}, true},
		{"email code", Policy{Methods: PublicMethods{EmailOTP: true}}, true},
		{"external providers", Policy{Methods: PublicMethods{Google: true, Telegram: true}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) { require.Equal(t, tc.required, tc.policy.RequiresEmailDelivery()) })
	}
}
