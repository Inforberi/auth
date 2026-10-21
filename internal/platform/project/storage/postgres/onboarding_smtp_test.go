package postgres

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

func TestOnboardingSMTPRedactionAndBounds(t *testing.T) {
	input := OnboardingSMTP{Password: "must-not-appear"}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		require.Equal(t, "[REDACTED onboarding SMTP]", fmt.Sprintf(format, input))
	}
	encoded, err := json.Marshal(input)
	require.NoError(t, err)
	require.JSONEq(t, `"[REDACTED onboarding SMTP]"`, string(encoded))
	target := &Target{}
	result, err := target.PrepareSMTP(t.Context(), credentials.OnboardingKeys{}, input, nil)
	require.ErrorIs(t, err, domain.ErrConflict)
	require.Zero(t, result)
}
