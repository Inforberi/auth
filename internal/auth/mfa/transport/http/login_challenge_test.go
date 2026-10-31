package mfahttp

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func TestLoginChallengeNextStep(t *testing.T) {
	for _, step := range []struct {
		enrollment, recovery bool
		status               string
	}{{false, false, "mfa_required"}, {true, false, "mfa_enrollment_required"}, {false, true, "mfa_recovery_required"}} {
		t.Run(step.status, func(t *testing.T) {
			response := httptest.NewRecorder()
			RespondChallenge(response, &service.LoginChallenge{Token: "challenge", Binding: "private-browser-binding", ExpiresAt: time.Now().Add(time.Minute), EnrollmentRequired: step.enrollment, RecoveryRequired: step.recovery})
			require.Equal(t, 202, response.Code)
			var body ChallengeResponse
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
			require.Equal(t, step.status, body.Status)
			require.NotContains(t, response.Body.String(), "private-browser-binding")
		})
	}
}
