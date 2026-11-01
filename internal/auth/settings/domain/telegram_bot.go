package domain

import (
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
)

var (
	ErrInvalidTelegramBot      = errors.New("invalid Telegram bot settings")
	ErrTelegramBotVerification = errors.New("telegram bot verification unavailable")
	ErrTelegramBotSecret       = errors.New("telegram bot secret unavailable")
	ErrTelegramBotLimited      = errors.New("telegram bot settings limited")
)

type TelegramBotToken struct {
	id    int64
	value string
}

func NewTelegramBotToken(value string) (TelegramBotToken, error) {
	if len(value) < 32 || len(value) > 160 {
		return TelegramBotToken{}, ErrInvalidTelegramBot
	}
	id, secret, found := strings.Cut(value, ":")
	number, err := strconv.ParseInt(id, 10, 64)
	if !found || err != nil || !validTelegramBotID(number) || strconv.FormatInt(number, 10) != id ||
		len(secret) < 20 || len(secret) > 128 || strings.IndexFunc(secret, func(r rune) bool {
		return r != '-' && !telegramWordRune(r)
	}) >= 0 {
		return TelegramBotToken{}, ErrInvalidTelegramBot
	}
	return TelegramBotToken{id: number, value: value}, nil
}

func (t TelegramBotToken) ID() int64      { return t.id }
func (t TelegramBotToken) Value() string  { return t.value }
func (TelegramBotToken) String() string   { return "[Telegram bot token]" }
func (TelegramBotToken) GoString() string { return "[Telegram bot token]" }

type TelegramBotIdentity struct {
	ID       int64
	Username string
}

func (b TelegramBotIdentity) Valid() bool {
	return validTelegramBotID(b.ID) && len(b.Username) >= 5 && len(b.Username) <= 32 &&
		strings.IndexFunc(b.Username, func(r rune) bool { return !telegramWordRune(r) }) < 0
}

func validTelegramBotID(id int64) bool { return id > 0 && id < 1<<52 }

func telegramWordRune(r rune) bool {
	return r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_'
}

func ValidTelegramWebhookSecret(secret string) bool {
	if len(secret) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(secret)
	return err == nil && len(decoded) == 32
}

type TelegramBotSnapshot struct {
	Version          int64  `json:"version"`
	BotID            int64  `json:"botId"`
	Username         string `json:"username"`
	TokenSet         bool   `json:"botTokenSet"`
	WebhookSecretSet bool   `json:"webhookSecretSet"`
}
