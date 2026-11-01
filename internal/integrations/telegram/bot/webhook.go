package telegrambot

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

var (
	ErrWebhook = errors.New("invalid Telegram webhook")
	ErrIgnored = errors.New("unsupported Telegram update")
)

type Webhook struct {
	bot    Bot
	secret [32]byte
}

func NewWebhook(bot Bot, secret string) (*Webhook, error) {
	if !validID(bot.id) || bot.username == "" || !validBinding(secret) {
		return nil, ErrInvalidInput
	}
	return &Webhook{bot: bot, secret: sha256.Sum256([]byte(secret))}, nil
}

func (b Bot) StartURL(binding string) (string, error) {
	if !validID(b.id) || b.username == "" || !validBinding(binding) {
		return "", ErrInvalidInput
	}
	return "https://t.me/" + b.username + "?start=" + binding, nil
}

type Start struct {
	BotID, UserID, UpdateID int64
	Binding                 string
}

type privateMessage struct {
	ID   int64 `json:"message_id"`
	Date int64 `json:"date"`
	From *struct {
		ID    int64 `json:"id"`
		IsBot *bool `json:"is_bot"`
	} `json:"from"`
	Chat struct {
		ID   int64  `json:"id"`
		Type string `json:"type"`
	} `json:"chat"`
	Text       string          `json:"text"`
	Forward    json.RawMessage `json:"forward_origin"`
	ViaBot     json.RawMessage `json:"via_bot"`
	SenderChat json.RawMessage `json:"sender_chat"`
	Business   string          `json:"business_connection_id"`
}

func (w *Webhook) DecodeStart(headers []string, body io.Reader, now time.Time) (Start, error) {
	if len(headers) != 1 || len(headers[0]) != 43 || body == nil || now.IsZero() {
		return Start{}, ErrWebhook
	}
	actual := sha256.Sum256([]byte(headers[0]))
	if subtle.ConstantTimeCompare(actual[:], w.secret[:]) != 1 {
		return Start{}, ErrWebhook
	}
	data, err := io.ReadAll(io.LimitReader(body, 16385))
	if err != nil || len(data) > 16384 {
		return Start{}, ErrWebhook
	}
	var update struct {
		ID      *int64          `json:"update_id"`
		Message *privateMessage `json:"message"`
	}
	if decodeObject(data, &update) != nil || update.ID == nil || *update.ID < 0 {
		return Start{}, ErrWebhook
	}
	m := update.Message
	if m == nil {
		return Start{}, ErrIgnored
	}
	return m.start(w.bot.id, *update.ID, now)
}

func (m *privateMessage) start(botID, updateID int64, now time.Time) (Start, error) {
	if m.From == nil || m.From.IsBot == nil || *m.From.IsBot || !validID(m.From.ID) || m.ID <= 0 ||
		m.Chat.Type != "private" || m.Chat.ID != m.From.ID || m.Business != "" ||
		len(m.Forward) != 0 || len(m.ViaBot) != 0 || len(m.SenderChat) != 0 ||
		m.Date <= 0 || time.Unix(m.Date, 0).Before(now.Add(-5*time.Minute)) || time.Unix(m.Date, 0).After(now.Add(30*time.Second)) {
		return Start{}, ErrIgnored
	}
	binding, command := strings.CutPrefix(m.Text, "/start ")
	if !command || !validBinding(binding) {
		return Start{}, ErrIgnored
	}
	return Start{BotID: botID, UserID: m.From.ID, UpdateID: updateID, Binding: binding}, nil
}

func validBinding(value string) bool {
	if len(value) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == 32
}
