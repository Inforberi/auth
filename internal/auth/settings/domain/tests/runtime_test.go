package domain_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestPolicyEmailDeliveryRequirement(t *testing.T) {
	for _, tc := range []struct {
		name     string
		policy   settingsdomain.Policy
		required bool
	}{
		{"closed", settingsdomain.Policy{}, false},
		{"dormant verification", settingsdomain.Policy{PasswordEmailVerification: settingsdomain.VerificationRequired}, false},
		{"password only", settingsdomain.Policy{Methods: settingsdomain.PublicMethods{Password: true}, PasswordEmailVerification: settingsdomain.VerificationDisabled}, false},
		{"optional verification", settingsdomain.Policy{Methods: settingsdomain.PublicMethods{Password: true}, PasswordEmailVerification: settingsdomain.VerificationOptional}, true},
		{"required verification", settingsdomain.Policy{Methods: settingsdomain.PublicMethods{Password: true}, PasswordEmailVerification: settingsdomain.VerificationRequired}, true},
		{"email code", settingsdomain.Policy{Methods: settingsdomain.PublicMethods{EmailOTP: true}}, true},
		{"external providers", settingsdomain.Policy{Methods: settingsdomain.PublicMethods{Google: true, Telegram: true}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) { require.Equal(t, tc.required, tc.policy.RequiresEmailDelivery()) })
	}
}
