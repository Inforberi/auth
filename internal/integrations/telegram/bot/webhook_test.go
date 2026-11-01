package telegrambot

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func testBinding() string { return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)) }

func webhookFixture(t *testing.T) (*Webhook, string, time.Time) {
	t.Helper()
	secret := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	webhook, err := NewWebhook(Bot{id: 123456789, username: "SecurityBot"}, secret)
	require.NoError(t, err)
	return webhook, secret, time.Unix(1793520000, 0)
}

func startUpdate(now time.Time) map[string]any {
	return map[string]any{"update_id": int64(7), "message": map[string]any{
		"message_id": 42, "date": now.Unix(), "text": "/start " + testBinding(),
		"from": map[string]any{"id": int64(1 << 40), "is_bot": false, "first_name": "User"},
		"chat": map[string]any{"id": int64(1 << 40), "type": "private"},
	}}
}

func TestWebhookPrivateStart(t *testing.T) {
	w, secret, now := webhookFixture(t)
	input := startUpdate(now)
	input["future_field"] = map[string]any{"valid": true}
	body, err := json.Marshal(input)
	require.NoError(t, err)
	start, err := w.DecodeStart([]string{secret}, bytes.NewReader(body), now)
	require.NoError(t, err)
	require.Equal(t, Start{BotID: 123456789, UserID: 1 << 40, UpdateID: 7, Binding: testBinding()}, start)
}

type unreadableBody struct{}

func (unreadableBody) Read([]byte) (int, error) { panic("untrusted webhook body was read") }

func TestWebhookAuthenticatesBeforeReading(t *testing.T) {
	w, secret, now := webhookFixture(t)
	for _, headers := range [][]string{nil, {secret, secret}, {""}, {strings.Repeat("x", 43)}, {secret + " "}} {
		_, err := w.DecodeStart(headers, unreadableBody{}, now)
		require.ErrorIs(t, err, ErrWebhook)
	}
	other, err := NewWebhook(Bot{id: 987654321, username: "OtherBot"}, testBinding())
	require.NoError(t, err)
	_, err = other.DecodeStart([]string{secret}, unreadableBody{}, now)
	require.ErrorIs(t, err, ErrWebhook)
}

func TestWebhookRejectsUnsafeMessages(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"group", func(m map[string]any) { m["chat"].(map[string]any)["type"] = "group" }},
		{"other chat", func(m map[string]any) { m["chat"].(map[string]any)["id"] = int64(2) }},
		{"bot sender", func(m map[string]any) { m["from"].(map[string]any)["is_bot"] = true }},
		{"missing bot flag", func(m map[string]any) { delete(m["from"].(map[string]any), "is_bot") }},
		{"missing sender", func(m map[string]any) { delete(m, "from") }},
		{"anonymous sender", func(m map[string]any) { m["sender_chat"] = map[string]any{"id": 1} }},
		{"forwarded", func(m map[string]any) { m["forward_origin"] = map[string]any{"type": "user"} }},
		{"via bot", func(m map[string]any) { m["via_bot"] = map[string]any{"id": 1} }},
		{"business", func(m map[string]any) { m["business_connection_id"] = "business" }},
		{"stale", func(m map[string]any) { m["date"] = m["date"].(int64) - 301 }},
		{"future", func(m map[string]any) { m["date"] = m["date"].(int64) + 31 }},
		{"zero message", func(m map[string]any) { m["message_id"] = 0 }},
		{"missing date", func(m map[string]any) { delete(m, "date") }},
		{"zero user", func(m map[string]any) { m["from"].(map[string]any)["id"] = 0 }},
		{"oversized user", func(m map[string]any) { m["from"].(map[string]any)["id"] = int64(1 << 52) }},
		{"non-command", func(m map[string]any) { m["text"] = "hello " + testBinding() }},
		{"start group", func(m map[string]any) { m["text"] = "/startgroup " + testBinding() }},
		{"short binding", func(m map[string]any) { m["text"] = "/start short" }},
		{"non-canonical binding", func(m map[string]any) { m["text"] = "/start " + strings.Repeat("a", 43) }},
		{"extra argument", func(m map[string]any) { m["text"] = "/start " + testBinding() + " extra" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, secret, now := webhookFixture(t)
			input := startUpdate(now)
			tc.change(input["message"].(map[string]any))
			body, err := json.Marshal(input)
			require.NoError(t, err)
			_, err = w.DecodeStart([]string{secret}, bytes.NewReader(body), now)
			require.ErrorIs(t, err, ErrIgnored)
		})
	}
}

func TestWebhookRejectsAmbiguousJSON(t *testing.T) {
	w, secret, now := webhookFixture(t)
	for _, body := range []string{
		`null`, `[]`, `{}`, `{"update_id":-1}`, `{"update_id":7,"update_id":8}`,
		`{"update_id":7,"message":{"from":{"id":1,"ID":2}}}`,
		`{"update_id":7} {}`, strings.Repeat("x", 16385),
		"{\"update_id\":7,\"unknown\":\"\xff\"}",
	} {
		_, err := w.DecodeStart([]string{secret}, strings.NewReader(body), now)
		require.ErrorIs(t, err, ErrWebhook)
	}
	_, err := w.DecodeStart([]string{secret}, io.LimitReader(strings.NewReader(`{"update_id":7}`), 1), now)
	require.ErrorIs(t, err, ErrWebhook)
	for _, body := range []string{`{"update_id":7,"edited_message":{}}`, `{"update_id":7,"callback_query":{}}`} {
		_, err := w.DecodeStart([]string{secret}, strings.NewReader(body), now)
		require.ErrorIs(t, err, ErrIgnored)
	}
}

func TestWebhookConfigurationAndLinkBounds(t *testing.T) {
	for _, bot := range []Bot{{}, {id: 1}, {username: "SecurityBot"}} {
		_, err := NewWebhook(bot, testBinding())
		require.ErrorIs(t, err, ErrInvalidInput)
		_, err = bot.StartURL(testBinding())
		require.ErrorIs(t, err, ErrInvalidInput)
	}
	bot := Bot{id: 1, username: "SecurityBot"}
	for _, binding := range []string{"", "short", testBinding() + "=", strings.Repeat("a", 43), strings.Repeat("x", 64)} {
		_, err := bot.StartURL(binding)
		require.ErrorIs(t, err, ErrInvalidInput)
		_, err = NewWebhook(bot, binding)
		require.ErrorIs(t, err, ErrInvalidInput)
	}
}
