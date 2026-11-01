package telegrambot

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestWebhookRegistration(t *testing.T) {
	credentials, err := NewCredentials(testToken)
	require.NoError(t, err)
	secret := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/bot"+testToken+"/setWebhook", r.URL.Path)
		var input struct {
			URL         string   `json:"url"`
			Secret      string   `json:"secret_token"`
			Updates     []string `json:"allowed_updates"`
			Connections int      `json:"max_connections"`
			Drop        bool     `json:"drop_pending_updates"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
		require.Equal(t, "https://project.example.test/api/v1/auth/mfa/telegram/webhook", input.URL)
		require.Equal(t, secret, input.Secret)
		require.Equal(t, []string{"message"}, input.Updates)
		require.Equal(t, 8, input.Connections)
		require.False(t, input.Drop)
		_, _ = w.Write([]byte(`{"ok":true,"result":true}`))
	})
	require.NoError(t, client.SetWebhook(t.Context(), credentials, "https://project.example.test/api/v1/auth/mfa/telegram/webhook", secret))
	for _, target := range []string{"http://project.example.test/", "https://user:pass@project.example.test/", "https://project.example.test/?secret=bad"} {
		require.ErrorIs(t, client.SetWebhook(t.Context(), credentials, target, secret), ErrInvalidInput)
	}
	_, err = BotFromSettings(domain.TelegramBotIdentity{})
	require.ErrorIs(t, err, ErrCredentials)
}
