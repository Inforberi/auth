package http

import (
	"bytes"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4/json"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type ExchangeRequest struct {
	Audience string                       `json:"audience" binding:"required"`
	Scope    []accessdomain.PermissionKey `json:"scope" binding:"required" swaggertype:"array,string"`
} // @name token_http.ExchangeRequest

type ExchangeResponse struct {
	AccessToken string    `json:"accessToken"`
	TokenType   string    `json:"tokenType"`
	ExpiresIn   int64     `json:"expiresIn"`
	ExpiresAt   time.Time `json:"expiresAt"`
	Audience    string    `json:"audience"`
	Scope       string    `json:"scope"`
} // @name token_http.ExchangeResponse

// @Summary Issue an access JWT from the current cookie session
// @Description Requires exact allowed Origin and a live completed cookie session. Does not refresh the session or MFA. Scope is restricted by the configured audience and current SQL grants. Strict tokens still require an online authority decision at the consumer.
// @Tags Tokens
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Accept json
// @Produce json
// @Param body body ExchangeRequest true "audience and permission keys"
// @Success 200 {object} ExchangeResponse
// @Failure 400 {object} httpx.ErrorResponse "invalid_json, invalid_token_request, ambiguous_credentials"
// @Failure 401 {object} httpx.ErrorResponse "unauthorized"
// @Failure 403 {object} httpx.ErrorResponse "invalid_origin, forbidden, email_not_verified, mfa_required"
// @Failure 429 {object} httpx.ErrorResponse "rate_limited"
// @Failure 503 {object} httpx.ErrorResponse "temporarily_unavailable"
// @Router /api/v1/auth/token/exchange [post]
func (h *Handler) Exchange(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if len(r.Header.Values("Authorization")) != 0 {
		httpx.Error(w, 400, "ambiguous_credentials", "use the session cookie only")
		return
	}
	auth, ok := sessionhttp.GetAuthContext(r.Context())
	if !ok {
		httpx.Error(w, 401, "unauthorized", "unauthorized")
		return
	}
	input, err := decodeExchange(w, r)
	if err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	result, err := h.service.Exchange(r.Context(), service.ExchangeInput{
		Actor: accessservice.Principal{UserID: auth.UserID, TokenHash: auth.TokenHash}, SessionID: auth.SessionID,
		Audience: input.Audience, Scope: input.Scope, IP: httpx.IP(r),
	})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, exchangeResponse(result))
}

func exchangeResponse(result *service.ExchangeResult) ExchangeResponse {
	keys := make([]string, len(result.Scope))
	for i, key := range result.Scope {
		keys[i] = string(key)
	}
	remaining := max(int64(0), result.ExpiresAt.Unix()-time.Now().Unix())
	return ExchangeResponse{
		AccessToken: result.Raw, TokenType: "Bearer", ExpiresIn: remaining,
		ExpiresAt: result.ExpiresAt, Audience: result.Audience, Scope: strings.Join(keys, " "),
	}
}

func decodeExchange(w http.ResponseWriter, r *http.Request) (ExchangeRequest, error) {
	var input ExchangeRequest
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return input, io.ErrUnexpectedEOF
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
	if err != nil {
		return input, err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || len(fields) != 2 || fields["audience"] == nil || fields["scope"] == nil ||
		bytes.Equal(bytes.TrimSpace(fields["audience"]), []byte("null")) || bytes.Equal(bytes.TrimSpace(fields["scope"]), []byte("null")) {
		return input, io.ErrUnexpectedEOF
	}
	return input, json.Unmarshal(data, &input)
}
