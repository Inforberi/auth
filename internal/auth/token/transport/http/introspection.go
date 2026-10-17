package http

import (
	"context"
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type IntrospectionService interface {
	Authenticate(string, string) (*service.IntrospectionClient, bool)
	Inspect(context.Context, *service.IntrospectionClient, string) (service.IntrospectionResult, error)
}

type IntrospectionHandler struct{ service IntrospectionService }

func NewIntrospection(svc IntrospectionService) *IntrospectionHandler {
	return &IntrospectionHandler{service: svc}
}

type IntrospectionRequest struct {
	Token string `json:"token"`
} // @name token_http.IntrospectionRequest

type IntrospectionResponse struct {
	Active    bool   `json:"active"`
	Issuer    string `json:"iss,omitempty"`
	Subject   string `json:"sub,omitempty"`
	SessionID string `json:"sid,omitempty"`
	ID        string `json:"jti,omitempty"`
	Audience  string `json:"audience,omitempty"`
	ExpiresAt int64  `json:"expiresAt,omitempty"`
	Scope     string `json:"scope,omitempty"`
} // @name token_http.IntrospectionResponse

// @Summary Check an access JWT against current session authority
// @Description Service-to-service HTTPS only. Dedicated per-consumer HTTP Basic credentials, not user Bearer/cookies. Invalid/inactive tokens return only active:false. Does not renew sessions. Custom protocol, not RFC 7662.
// @Tags Tokens
// @Accept json
// @Produce json
// @Param Authorization header string true "Basic service client ID and secret"
// @Param body body IntrospectionRequest true "Full access JWT"
// @Success 200 {object} IntrospectionResponse
// @Failure 400 {object} httpx.ErrorResponse "invalid_json"
// @Failure 401 {object} httpx.ErrorResponse "unauthorized_service"
// @Failure 403 {object} httpx.ErrorResponse "forbidden"
// @Failure 429 {object} httpx.ErrorResponse "rate_limited"
// @Failure 503 {object} httpx.ErrorResponse "temporarily_unavailable"
// @Router /api/v1/internal/auth/token/introspect [post]
func (h *IntrospectionHandler) Inspect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodOptions || len(r.Header.Values("Origin")) != 0 || len(r.Header.Values("Cookie")) != 0 || r.URL.RawQuery != "" || r.URL.ForceQuery {
		httpx.Error(w, 403, "forbidden", "service transport required")
		return
	}
	values := r.Header.Values("Authorization")
	if len(values) != 1 || len(values[0]) > 256 {
		unauthorizedService(w)
		return
	}
	id, secret, ok := r.BasicAuth()
	if !ok {
		unauthorizedService(w)
		return
	}
	client, ok := h.service.Authenticate(id, secret)
	if !ok {
		unauthorizedService(w)
		return
	}
	var input IntrospectionRequest
	if !decodeNative(w, r, &input, []string{"token"}) {
		return
	}
	result, err := h.service.Inspect(r.Context(), client, input.Token)
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, IntrospectionResponse{
		Active: result.Active, Issuer: result.Issuer, Subject: result.Subject, SessionID: result.SessionID,
		ID: result.ID, Audience: result.Audience, ExpiresAt: result.ExpiresAt, Scope: result.Scope,
	})
}

func unauthorizedService(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="auth-introspection", charset="UTF-8"`)
	httpx.Error(w, 401, "unauthorized_service", "unauthorized service")
}
