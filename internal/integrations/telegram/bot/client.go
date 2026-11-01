package telegrambot

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	ErrInvalidInput = errors.New("invalid Telegram bot input")
	ErrUnavailable  = errors.New("telegram bot unavailable")
	ErrBusy         = errors.New("telegram bot capacity exhausted")
	ErrCredentials  = errors.New("invalid Telegram bot credentials")
	ErrBlocked      = errors.New("telegram private channel unavailable")
)

type Credentials struct {
	token string
	id    int64
}

func NewCredentials(token string) (Credentials, error) {
	if len(token) < 32 || len(token) > 160 {
		return Credentials{}, ErrCredentials
	}
	id, secret, found := strings.Cut(token, ":")
	value, err := strconv.ParseInt(id, 10, 64)
	if !found || err != nil || !validID(value) || strconv.FormatInt(value, 10) != id ||
		len(secret) < 20 || len(secret) > 128 || strings.IndexFunc(secret, func(r rune) bool {
		return r != '-' && !wordRune(r)
	}) >= 0 {
		return Credentials{}, ErrCredentials
	}
	return Credentials{token: token, id: value}, nil
}

func (Credentials) String() string   { return "[Telegram bot credentials]" }
func (Credentials) GoString() string { return "[Telegram bot credentials]" }

type Client struct {
	http      *http.Client
	transport *http.Transport
	slots     chan struct{}
	lifetime  context.Context //nolint:containedctx // Transport lifetime cancels all calls at shutdown; request contexts remain per-call.
	cancel    context.CancelFunc
}

func New(ctx context.Context, parallelism int) (*Client, error) {
	if ctx == nil || parallelism < 1 || parallelism > 64 {
		return nil, ErrInvalidInput
	}
	transport := &http.Transport{
		DialContext:     (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 3 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16384,
		MaxConnsPerHost: parallelism, MaxIdleConnsPerHost: parallelism, MaxIdleConns: parallelism,
		IdleConnTimeout: 90 * time.Second, ForceAttemptHTTP2: true,
	}
	lifetime, cancel := context.WithCancel(ctx)
	httpClient := &http.Client{
		Transport: transport, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return &Client{http: httpClient, transport: transport, slots: make(chan struct{}, parallelism), lifetime: lifetime, cancel: cancel}, nil
}

func (c *Client) Close() {
	c.cancel()
	c.transport.CloseIdleConnections()
}

type Bot struct {
	id       int64
	username string
}

func (b Bot) ID() int64 { return b.id }

func (c *Client) Check(ctx context.Context, credentials Credentials) (Bot, error) {
	raw, err := c.call(ctx, credentials, "getMe", struct{}{})
	if err != nil {
		return Bot{}, err
	}
	var user struct {
		ID       int64  `json:"id"`
		IsBot    bool   `json:"is_bot"`
		Username string `json:"username"`
	}
	if json.Unmarshal(raw, &user) != nil || !user.IsBot || user.ID != credentials.id ||
		len(user.Username) < 5 || len(user.Username) > 32 || strings.IndexFunc(user.Username, func(r rune) bool {
		return !wordRune(r)
	}) >= 0 {
		return Bot{}, ErrUnavailable
	}
	return Bot{id: user.ID, username: user.Username}, nil
}

func (c *Client) SendCode(ctx context.Context, credentials Credentials, userID int64, code string) error {
	if !validID(userID) || len(code) != 8 || strings.IndexFunc(code, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return ErrInvalidInput
	}
	raw, err := c.call(ctx, credentials, "sendMessage", struct {
		ChatID         int64  `json:"chat_id"`
		Text           string `json:"text"`
		ProtectContent bool   `json:"protect_content"`
	}{userID, "Код безопасности: " + code + ". Не сообщайте его другим людям.", true})
	if err != nil {
		return err
	}
	var sent struct {
		ID   int64 `json:"message_id"`
		Chat struct {
			ID   int64  `json:"id"`
			Type string `json:"type"`
		} `json:"chat"`
	}
	if json.Unmarshal(raw, &sent) != nil || sent.ID <= 0 || sent.Chat.ID != userID || sent.Chat.Type != "private" {
		return ErrUnavailable
	}
	return nil
}

func validID(id int64) bool { return id > 0 && id < 1<<52 }

func wordRune(r rune) bool {
	return r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_'
}
