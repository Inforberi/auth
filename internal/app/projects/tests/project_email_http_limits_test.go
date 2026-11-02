package projects_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
)

func trackEmailHTTPLimits(t *testing.T, f *emailIsolationFixture) {
	t.Helper()
	groups := [2][]string{
		{
			"email-binding:confirm:user:" + httpOwnerID,
			"resend-ip:127.0.0.1", "confirm-ip:127.0.0.1", "email-change-request-ip:127.0.0.1", "email-change-confirm:127.0.0.1", "email-change-report:127.0.0.1",
			"email-binding:request:actor:" + httpOwnerID, "email-binding:request:ip:127.0.0.1", "email-binding:request:project", "email-binding:request:user:" + emailHTTPBindingUser, "email-binding:confirm:ip:127.0.0.1", "email-binding:confirm:user:" + emailHTTPBindingUser, "email-binding:confirm:project",
		},
		{"forgot-ip:127.0.0.1", "reset-ip:127.0.0.1", "activation-ip:127.0.0.1", "protected-recovery-ip:127.0.0.1", "temporary-password-setup-ip:127.0.0.1", "reauth-user:" + httpOwnerID, "reauth-user:" + httpIsolationUser},
	}
	for i, key := range f.projects.projects {
		scope, err := realmscope.New("project", string(key.Binding.ProjectID))
		require.NoError(t, err)
		for j, legacy := range []string{"auth:email-verification:limit:", "auth:password-recovery:limit:"} {
			purpose := "email-verification-limit"
			if j == 1 {
				purpose = "password-limit"
			}
			prefix, err := scope.RedisPrefix(purpose, legacy)
			require.NoError(t, err)
			for _, logical := range groups[j] {
				f.projects.redisKeys[prefix+f.ciphers[i][j].Digest(logical)] = struct{}{}
			}
		}
		// Login subjects vary after email change and account provisioning; keep exact keys only.
		for _, email := range []string{httpOwnerEmail, httpIsolationEmail, "isolation-new@example.test", "isolation-temp@example.test"} {
			f.projects.redisKeys[f.projects.passwordPrefix[i]+f.projects.passwordCipher[i].Digest("login-email:"+strings.ToLower(email))] = struct{}{}
		}
	}
}
