package telegrambot

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

// The caller loads identity from verified settings, never from an HTTP request.
func BotFromSettings(identity domain.TelegramBotIdentity) (Bot, error) {
	if !identity.Valid() {
		return Bot{}, ErrCredentials
	}
	return Bot{id: identity.ID, username: identity.Username}, nil
}

func (c *Client) SetWebhook(ctx context.Context, credentials Credentials, destination, secret string) error {
	u, err := url.Parse(destination)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !domain.ValidTelegramWebhookSecret(secret) {
		return ErrInvalidInput
	}
	raw, err := c.call(ctx, credentials, "setWebhook", struct {
		URL         string   `json:"url"`
		Secret      string   `json:"secret_token"`
		Updates     []string `json:"allowed_updates"`
		Connections int      `json:"max_connections"`
	}{destination, secret, []string{"message"}, 8})
	if err != nil {
		return err
	}
	var success bool
	if json.Unmarshal(raw, &success) != nil || !success {
		return ErrUnavailable
	}
	return nil
}
