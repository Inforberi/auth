package authjwt

import (
	"bytes"
	"context"
	"net/http"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4/json"
)

type introspectionResponse struct {
	Active    *bool  `json:"active"`
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	SessionID string `json:"sid"`
	ID        string `json:"jti"`
	Audience  string `json:"audience"`
	ExpiresAt int64  `json:"expiresAt"`
	Scope     string `json:"scope"`
}

func (c *Consumer) introspect(ctx context.Context, raw string, claims Claims) (string, error) {
	data, err := json.Marshal(struct {
		Token string `json:"token"`
	}{Token: raw})
	if err != nil {
		return "", ErrAuthorityUnavailable
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.IntrospectionURL, bytes.NewReader(data))
	if err != nil {
		return "", ErrConfiguration
	}
	// A POST with a body but no GetBody/Idempotency-Key is not retried by the shared HTTP/1 transport.
	req.GetBody = nil
	req.SetBasicAuth(c.config.ClientID, c.config.ClientSecret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-store")
	response, err := c.request(req, 8192)
	if err != nil {
		return "", ErrAuthorityUnavailable
	}
	if response.status == http.StatusTooManyRequests {
		return "", ErrBusy
	}
	if response.status != http.StatusOK || !hasNoStore(response.header) {
		return "", ErrAuthorityUnavailable
	}
	return correlateIntrospection(response.data, claims)
}

func correlateIntrospection(data []byte, claims Claims) (string, error) {
	var response introspectionResponse
	if decodeObject(data, &response, "active", "iss", "sub", "sid", "jti", "audience", "expiresAt", "scope") != nil || response.Active == nil {
		return "", ErrAuthorityUnavailable
	}
	if !*response.Active {
		var fields map[string]json.RawMessage
		if json.Unmarshal(data, &fields) != nil || len(fields) != 1 {
			return "", ErrAuthorityUnavailable
		}
		return "", ErrInvalidToken
	}
	if response.Issuer != claims.Issuer || response.Subject != claims.Subject || response.SessionID != claims.SessionID || response.ID != claims.ID ||
		response.Audience != claims.Audience || response.ExpiresAt != claims.ExpiresAt || !validScope(response.Scope) {
		return "", ErrAuthorityUnavailable
	}
	maximum := strings.Split(claims.Scope, " ")
	for _, key := range strings.Split(response.Scope, " ") {
		if _, found := slices.BinarySearch(maximum, key); !found {
			return "", ErrAuthorityUnavailable
		}
	}
	return response.Scope, nil
}

func hasNoStore(header http.Header) bool {
	for _, value := range header.Values("Cache-Control") {
		for _, directive := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(directive), "no-store") {
				return true
			}
		}
	}
	return false
}
