package domain_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestPolicyChangeRequiresTrustedCapabilities(t *testing.T) {
	before := domain.Snapshot{Version: 3}
	password := domain.Policy{Methods: domain.PublicMethods{Password: true}, PasswordEmailVerification: domain.VerificationDisabled}
	ready := domain.PolicyRuntime{Configured: true, Methods: password.Methods}
	for _, tc := range []struct {
		name    string
		runtime domain.PolicyRuntime
		next    domain.Policy
		version int64
		want    error
	}{
		{"version conflict precedes readiness", domain.PolicyRuntime{}, password, 2, domain.ErrPolicyConflict},
		{"unconfigured", domain.PolicyRuntime{}, password, 3, domain.ErrMethodNotReady},
		{"unavailable method", domain.PolicyRuntime{Configured: true}, password, 3, domain.ErrMethodNotReady},
		{"password ready", ready, password, 3, nil},
		{"native unavailable", ready, domain.Policy{TokenIssuance: domain.TokenIssuance{Native: true}}, 3, domain.ErrMethodNotReady},
		{"exchange unavailable", ready, domain.Policy{TokenIssuance: domain.TokenIssuance{SessionExchange: true}}, 3, domain.ErrMethodNotReady},
		{"stored mail unavailable", domain.PolicyRuntime{Configured: true, Methods: password.Methods, RequireStoredProviders: true}, domain.Policy{Methods: password.Methods, PasswordEmailVerification: domain.VerificationRequired}, 3, domain.ErrMethodNotReady},
		{"verification unavailable", domain.PolicyRuntime{Configured: true, Methods: password.Methods, Dependencies: &domain.DependencyVersions{}}, domain.Policy{Methods: password.Methods, PasswordEmailVerification: domain.VerificationOptional}, 3, domain.ErrMethodNotReady},
		{"verification ready", domain.PolicyRuntime{Configured: true, Methods: password.Methods, RequireStoredProviders: true, EmailDeliveryReady: true, VerificationReady: true, Dependencies: &domain.DependencyVersions{}}, domain.Policy{Methods: password.Methods, PasswordEmailVerification: domain.VerificationRequired}, 3, nil},
		{"mail capability unnecessary for plain password", domain.PolicyRuntime{Configured: true, Methods: password.Methods, RequireStoredProviders: true, Dependencies: &domain.DependencyVersions{}}, password, 3, nil},
	} {
		t.Run(tc.name, func(t *testing.T) { require.ErrorIs(t, tc.runtime.CheckChange(before, tc.version, tc.next), tc.want) })
	}
}
