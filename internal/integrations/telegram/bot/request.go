package telegrambot

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/infra/jsonconfig"
)

func (c *Client) call(ctx context.Context, credentials Credentials, method string, input any) (result json.RawMessage, err error) {
	if ctx == nil || credentials.id == 0 || credentials.token == "" || method != "getMe" && method != "sendMessage" {
		return nil, ErrInvalidInput
	}
	if ctx.Err() != nil || c.lifetime.Err() != nil {
		return nil, ErrUnavailable
	}
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	default:
		return nil, ErrBusy
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	stop := context.AfterFunc(c.lifetime, cancel) //nolint:contextcheck // Owner shutdown cancels the request's inherited timeout context.
	defer stop()
	body, err := json.Marshal(input)
	if err != nil {
		return nil, ErrInvalidInput
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.telegram.org/bot"+credentials.token+"/"+method, bytes.NewReader(body))
	if err != nil {
		return nil, ErrUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		// net/url errors include the Bot API token in the request path.
		return nil, ErrUnavailable
	}
	defer func() {
		if closeErr := response.Body.Close(); closeErr != nil && err == nil {
			result, err = nil, ErrUnavailable
		}
	}()
	return readResponse(response)
}

func readResponse(response *http.Response) (json.RawMessage, error) {
	data, readErr := io.ReadAll(io.LimitReader(response.Body, 32769))
	if readErr != nil || len(data) > 32768 {
		return nil, ErrUnavailable
	}
	var envelope struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  int             `json:"error_code"`
	}
	if decodeObject(data, &envelope) != nil {
		return nil, ErrUnavailable
	}
	if response.StatusCode == http.StatusUnauthorized || envelope.Error == http.StatusUnauthorized {
		return nil, ErrCredentials
	}
	if response.StatusCode == http.StatusForbidden || envelope.Error == http.StatusForbidden {
		return nil, ErrBlocked
	}
	if response.StatusCode != http.StatusOK || !envelope.OK || envelope.Error != 0 || len(envelope.Result) == 0 {
		return nil, ErrUnavailable
	}
	return envelope.Result, nil
}

func decodeObject(data []byte, destination any) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		return ErrInvalidInput
	}
	// Telegram may add fields; retain the existing duplicate/depth/UTF-8 checks without rejecting them.
	var raw json.RawMessage
	if jsonconfig.Decode(data, &raw) != nil || json.Unmarshal(raw, destination) != nil {
		return ErrInvalidInput
	}
	return nil
}
