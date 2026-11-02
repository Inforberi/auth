package projects_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	telegrambot "github.com/Inforberi/financial-intelligence/internal/integrations/telegram/bot"
)

type telegramHTTPBot struct {
	mu      sync.Mutex
	code    string
	secrets map[string]string
	failure bool
}

func (b *telegramHTTPBot) VerifyTelegramBot(_ context.Context, token settingsdomain.TelegramBotToken) (settingsdomain.TelegramBotIdentity, error) {
	return settingsdomain.TelegramBotIdentity{ID: token.ID(), Username: fmt.Sprintf("Security%dBot", token.ID())}, nil
}

func (b *telegramHTTPBot) SendCode(_ context.Context, _ telegrambot.Credentials, _ int64, code string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failure {
		return errors.New("synthetic Telegram unavailable")
	}
	b.code = code
	return nil
}

func (b *telegramHTTPBot) SetWebhook(_ context.Context, _ telegrambot.Credentials, target, secret string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.secrets == nil {
		b.secrets = make(map[string]string)
	}
	b.secrets[target] = secret
	return nil
}

func (b *telegramHTTPBot) latest() string { b.mu.Lock(); defer b.mu.Unlock(); return b.code }
func (b *telegramHTTPBot) secret(target string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.secrets[target]
}
func (b *telegramHTTPBot) fail(value bool) { b.mu.Lock(); defer b.mu.Unlock(); b.failure = value }

func (f emailMFAHTTPFixture) trackTelegramLimits(t *testing.T, binding string) {
	t.Helper()
	for i := range f.projects.projects {
		for _, logical := range []string{"telegram-login:resend:" + httpIsolationUser, "telegram-factor:user:" + httpIsolationUser, "telegram-factor:project", "mfa-preference:user:" + httpIsolationUser, "mfa-preference:project", "user:" + httpIsolationUser, "login:factor-user:" + httpIsolationUser} {
			f.projects.redisKeys[f.prefix[i]+f.mfa[i].Digest(logical)] = struct{}{}
		}
		for _, raw := range []string{"telegram-bot-settings:user:" + httpOwnerID, "telegram-bot-settings:project", "telegram-webhook:project", "telegram-webhook:ip:" + f.mfa[i].Digest("127.0.0.1"), "project", "login:ip:" + f.mfa[i].Digest("127.0.0.1")} {
			f.projects.redisKeys[f.prefix[i]+raw] = struct{}{}
		}
		for _, phase := range []string{"request", "confirm"} {
			for _, suffix := range []string{":user:" + httpIsolationUser, ":ip:127.0.0.1", ":project"} {
				f.projects.redisKeys[f.prefix[i]+f.channel[i].Digest("telegram-channel:"+phase+suffix)] = struct{}{}
			}
		}
		for _, logical := range []string{"telegram-channel:update:user:1099511627776", "telegram-channel:update:project", "telegram-channel:update:binding:" + binding} {
			f.projects.redisKeys[f.prefix[i]+f.channel[i].Digest(logical)] = struct{}{}
		}
	}
}
