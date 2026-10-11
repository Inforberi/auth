package http

import (
	"net/http"
	"net/url"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type CallbackResponse struct {
	Status string `json:"status"`
}

// @Summary Complete Telegram OIDC login
// @Description Provider redirect bound to single-use state, PKCE, nonce and flow cookie. Login sets __Host-session; linking requires the unchanged fresh session and never creates or replaces it. No email auto-merge. Restart after a failed or lost callback.
// @Tags Auth
// @Param code query string true "Authorization code"
// @Param state query string true "Single-use state"
// @Produce json
// @Success 200 {object} CallbackResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse "fresh_auth_required"
// @Failure 409 {object} httpx.ErrorResponse "identity_conflict"
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/telegram/callback [get]
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(values["code"]) != 1 || len(values["state"]) != 1 || len(values["error"]) != 0 {
		h.respondError(w, r, domain.ErrInvalidFlow)
		return
	}
	cookies := r.CookiesNamed(flowCookie)
	if len(cookies) != 1 {
		h.respondError(w, r, domain.ErrInvalidFlow)
		return
	}
	// Missing or ambiguous session cookies cannot authorize linking; ordinary login does not require one.
	var sessionToken string
	if len(r.CookiesNamed(sessionhttp.SessionCookieName)) == 1 {
		if token, err := sessionhttp.GetSessionCookie(r); err == nil {
			sessionToken = token
		}
	}
	result, err := h.service.Callback(r.Context(), service.CallbackInput{
		Code: values.Get("code"), State: values.Get("state"), Binding: cookies[0].Value,
		UserAgent: httpx.UserAgent(r), IP: httpx.IP(r),
		SessionToken: sessionToken,
	})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	setFlowCookie(w, "")
	if !result.Linked {
		sessionhttp.SetSessionCookie(w, result.Session.RawToken, result.Session.ExpiresAt)
	}
	httpx.JSON(w, 200, CallbackResponse{Status: "ok"})
}
