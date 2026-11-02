package domain_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestAuthPolicyUpdateNormalization(t *testing.T) {
	command := domain.AuthPolicyUpdate{OperationID: "22222222-2222-4222-8222-222222222222", ProjectID: "11111111-1111-4111-8111-111111111111", ExpectedVersion: 1, ExpectedGeneration: 1, ExpectedPolicyVersion: 1, Reason: " maintenance ", Policy: settingsdomain.Policy{PasswordEmailVerification: settingsdomain.VerificationDisabled}}
	normalized, err := command.Normalize()
	require.NoError(t, err)
	require.Equal(t, "maintenance", normalized.Reason)
	for _, change := range []func(*domain.AuthPolicyUpdate){
		func(c *domain.AuthPolicyUpdate) { c.OperationID = "" }, func(c *domain.AuthPolicyUpdate) { c.ProjectID = "invalid" },
		func(c *domain.AuthPolicyUpdate) { c.ExpectedVersion = 0 }, func(c *domain.AuthPolicyUpdate) { c.ExpectedGeneration = 0 }, func(c *domain.AuthPolicyUpdate) { c.ExpectedPolicyVersion = 0 },
		func(c *domain.AuthPolicyUpdate) { c.Reason = "  " }, func(c *domain.AuthPolicyUpdate) { c.Reason = strings.Repeat("x", 1025) },
	} {
		invalid := command
		change(&invalid)
		_, err = invalid.Normalize()
		require.ErrorIs(t, err, domain.ErrInvalidProject)
	}
	invalid := command
	invalid.Policy.PasswordEmailVerification = "unknown"
	_, err = invalid.Normalize()
	require.ErrorIs(t, err, settingsdomain.ErrInvalidPolicy)
}
