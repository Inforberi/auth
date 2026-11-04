package browser

import (
	"context"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	telegrambot "github.com/Inforberi/financial-intelligence/internal/integrations/telegram/bot"
)

type webhookBoundaryStub struct {
	allowed                   bool
	budgetCalls, receiveCalls int
}

func (s *webhookBoundaryStub) AllowTelegramWebhook(context.Context) (bool, error) {
	s.budgetCalls++
	return s.allowed, nil
}

func (s *webhookBoundaryStub) ReceiveTelegramWebhook(context.Context, func(*telegrambot.Webhook) (telegrambot.Start, error)) error {
	s.receiveCalls++
	return nil
}

type unreadWebhookBody struct{ t *testing.T }

func (b unreadWebhookBody) Read([]byte) (int, error) {
	b.t.Fatal("body read before admission")
	return 0, io.EOF
}
func (unreadWebhookBody) Close() error { return nil }

func TestTelegramWebhookRejectsBrowserBeforeBudgetAndBody(t *testing.T) {
	for _, header := range []string{"Origin", "Cookie", "Authorization"} {
		t.Run(header, func(t *testing.T) {
			s := &webhookBoundaryStub{allowed: true}
			r := httptest.NewRequest("POST", "https://project.test/webhook", nil)
			r.Header.Set(header, "unexpected")
			r.Body = unreadWebhookBody{t: t}
			w := httptest.NewRecorder()
			telegramWebhookHandler(s)(w, r)
			require.Equal(t, 403, w.Code)
			require.Zero(t, s.budgetCalls)
			require.Zero(t, s.receiveCalls)
		})
	}
}

func TestTelegramWebhookRateLimitPrecedesReceiveAndBody(t *testing.T) {
	s := &webhookBoundaryStub{}
	r := httptest.NewRequest("POST", "https://project.test/webhook", nil)
	r.Body = unreadWebhookBody{t: t}
	w := httptest.NewRecorder()
	telegramWebhookHandler(s)(w, r)
	require.Equal(t, 429, w.Code)
	require.Equal(t, "60", w.Header().Get("Retry-After"))
	require.Equal(t, 1, s.budgetCalls)
	require.Zero(t, s.receiveCalls)
}
