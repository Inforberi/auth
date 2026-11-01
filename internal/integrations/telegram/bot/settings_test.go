package telegrambot

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestSettingsVerifier(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"verified", 200, `{"ok":true,"result":{"id":123456789,"is_bot":true,"username":"SecurityBot"}}`, nil},
		{"wrong identity", 200, `{"ok":true,"result":{"id":987654321,"is_bot":true,"username":"SecurityBot"}}`, domain.ErrTelegramBotVerification},
		{"credentials", 401, `{"ok":false,"error_code":401}`, domain.ErrInvalidTelegramBot},
		{"unavailable", 503, `{"ok":false}`, domain.ErrTelegramBotVerification},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			token, err := domain.NewTelegramBotToken(testToken)
			require.NoError(t, err)
			identity, err := client.VerifyTelegramBot(t.Context(), token)
			if tc.want != nil {
				require.ErrorIs(t, err, tc.want)
				require.NotContains(t, err.Error(), testToken)
				return
			}
			require.NoError(t, err)
			require.True(t, identity.Valid())
			require.Equal(t, token.ID(), identity.ID)
		})
	}
}
