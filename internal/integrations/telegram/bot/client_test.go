package telegrambot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testToken = "123456789:abcdefghijklmnopqrstuvwxyz_0123456789"

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testClient(t *testing.T, handler http.HandlerFunc) (*Client, Credentials) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	client, err := New(t.Context(), 2)
	require.NoError(t, err)
	t.Cleanup(client.Close)
	target, err := url.Parse(server.URL)
	require.NoError(t, err)
	transport := server.Client().Transport
	t.Cleanup(func() { transport.(*http.Transport).CloseIdleConnections() })
	client.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme != "https" || r.URL.Host != "api.telegram.org" || r.Method != "POST" ||
			r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" {
			return nil, errors.New("unexpected Bot API destination or request")
		}
		copyRequest := r.Clone(r.Context())
		copyURL := *r.URL
		copyURL.Scheme, copyURL.Host = target.Scheme, target.Host
		copyRequest.URL = &copyURL
		return transport.RoundTrip(copyRequest)
	})
	credentials, err := NewCredentials(testToken)
	require.NoError(t, err)
	return client, credentials
}

func TestBotIdentityAndCode(t *testing.T) {
	requests := make(chan map[string]any, 2)
	client, credentials := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		var input map[string]any
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, "bad request", 400)
			return
		}
		requests <- input
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/bot" + testToken + "/getMe":
			_, _ = w.Write([]byte(` {"ok":true,"result":{"id":123456789,"is_bot":true,"username":"SecurityBot","future_field":true}} `))
		case "/bot" + testToken + "/sendMessage":
			_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":42,"chat":{"id":1099511627776,"type":"private"}}}`))
		default:
			http.Error(w, "unexpected method", 400)
		}
	})
	bot, err := client.Check(t.Context(), credentials)
	require.NoError(t, err)
	require.EqualValues(t, 123456789, bot.ID())
	require.Empty(t, <-requests)
	require.NoError(t, client.SendCode(t.Context(), credentials, 1<<40, "12345678"))
	input := <-requests
	require.Equal(t, float64(1<<40), input["chat_id"])
	require.Contains(t, input["text"], "12345678")
	require.Equal(t, true, input["protect_content"])
	require.NotContains(t, input, "parse_mode")
	require.NotContains(t, input, "allow_paid_broadcast")
	link, err := bot.StartURL(testBinding())
	require.NoError(t, err)
	require.Equal(t, "https://t.me/SecurityBot?start="+testBinding(), link)
}

func TestBotAPIRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"wrong bot", 200, `{"ok":true,"result":{"id":987654321,"is_bot":true,"username":"SecurityBot"}}`, ErrUnavailable},
		{"human", 200, `{"ok":true,"result":{"id":123456789,"is_bot":false,"username":"SecurityBot"}}`, ErrUnavailable},
		{"username injection", 200, `{"ok":true,"result":{"id":123456789,"is_bot":true,"username":"other/path"}}`, ErrUnavailable},
		{"duplicate identity", 200, `{"ok":true,"result":{"id":123456789,"id":987654321}}`, ErrUnavailable},
		{"trailing JSON", 200, `{"ok":true,"result":{}} {}`, ErrUnavailable},
		{"null result", 200, `{"ok":true,"result":null}`, ErrUnavailable},
		{"oversize", 200, strings.Repeat("x", 32769), ErrUnavailable},
		{"unauthorized", 401, `{"ok":false,"error_code":401,"description":"` + testToken + `"}`, ErrCredentials},
		{"blocked", 403, `{"ok":false,"error_code":403}`, ErrBlocked},
		{"rate limited", 429, `{"ok":false,"error_code":429,"parameters":{"retry_after":20}}`, ErrUnavailable},
		{"server fault", 503, `{"ok":false}`, ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, credentials := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			_, err := client.Check(t.Context(), credentials)
			require.ErrorIs(t, err, tc.want)
			require.NotContains(t, err.Error(), testToken)
		})
	}
}

func TestBotRejectsRedirectAndWrongRecipient(t *testing.T) {
	t.Run("redirect", func(t *testing.T) {
		client, credentials := testClient(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://untrusted.example/collect", http.StatusTemporaryRedirect)
		})
		_, err := client.Check(t.Context(), credentials)
		require.ErrorIs(t, err, ErrUnavailable)
	})
	t.Run("wrong recipient", func(t *testing.T) {
		client, credentials := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":1,"chat":{"id":2,"type":"private"}}}`))
		})
		require.ErrorIs(t, client.SendCode(t.Context(), credentials, 1, "12345678"), ErrUnavailable)
	})
}

func TestBotLocalBounds(t *testing.T) {
	for _, token := range []string{"", "123:short", "01:" + strings.Repeat("a", 35), "-1:" + strings.Repeat("a", 35), "123:" + strings.Repeat("a", 32) + "/path", strings.Repeat("x", 161)} {
		_, err := NewCredentials(token)
		require.ErrorIs(t, err, ErrCredentials)
	}
	for _, limit := range []int{0, -1, 65} {
		_, err := New(t.Context(), limit)
		require.ErrorIs(t, err, ErrInvalidInput)
	}
	client, err := New(t.Context(), 1)
	require.NoError(t, err)
	t.Cleanup(client.Close)
	credentials, err := NewCredentials(testToken)
	require.NoError(t, err)
	require.NotContains(t, fmt.Sprintf("%v %+v %#v", credentials, credentials, credentials), testToken)
	client.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("invalid input reached the network")
		return nil, ErrUnavailable
	})
	for _, code := range []string{"", "1234567", "123456789", "1234x678", "１２３４５６７８"} {
		require.ErrorIs(t, client.SendCode(t.Context(), credentials, 1, code), ErrInvalidInput)
	}
	for _, id := range []int64{0, -1, 1 << 52} {
		require.ErrorIs(t, client.SendCode(t.Context(), credentials, id, "12345678"), ErrInvalidInput)
	}
}

func TestBotCapacityCancellationAndClose(t *testing.T) {
	client, err := New(t.Context(), 1)
	require.NoError(t, err)
	t.Cleanup(client.Close)
	credentials, err := NewCredentials(testToken)
	require.NoError(t, err)
	started := make(chan struct{})
	client.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		close(started)
		<-r.Context().Done()
		return nil, fmt.Errorf("transport failure for %s: %w", r.URL, r.Context().Err())
	})
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	go func() { _, err := client.Check(ctx, credentials); done <- err }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("request did not start")
	}
	_, err = client.Check(ctx, credentials)
	require.ErrorIs(t, err, ErrBusy)
	client.Close()
	select {
	case err = <-done:
		require.ErrorIs(t, err, ErrUnavailable)
		require.NotContains(t, err.Error(), testToken)
	case <-ctx.Done():
		t.Fatal("close did not cancel the request")
	}
	_, err = client.Check(t.Context(), credentials)
	require.ErrorIs(t, err, ErrUnavailable)
}

type closeFailure struct{ io.Reader }

func (closeFailure) Close() error { return errors.New("synthetic close failure: " + testToken) }

func TestBotResponseCloseFailure(t *testing.T) {
	client, err := New(t.Context(), 1)
	require.NoError(t, err)
	t.Cleanup(client.Close)
	credentials, err := NewCredentials(testToken)
	require.NoError(t, err)
	client.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: closeFailure{strings.NewReader(`{"ok":true,"result":{"id":123456789,"is_bot":true,"username":"SecurityBot"}}`)}}, nil
	})
	result, err := client.Check(t.Context(), credentials)
	require.ErrorIs(t, err, ErrUnavailable)
	require.Empty(t, result)
	require.NotContains(t, err.Error(), testToken)
}
