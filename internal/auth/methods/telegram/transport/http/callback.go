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
// @Description Provider browser redirect, bound to single-use state, PKCE, nonce and flow cookie. Sets only the existing __Host-session cookie. No UserInfo/email auto-merge. Restart login after a failed or lost callback.
// @Tags Auth
// @Param code query string true "Authorization code"
// @Param state query string true "Single-use state"
// @Produce json
// @Success 200 {object} CallbackResponse
// @Failure 400 {object} httpx.ErrorResponse
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
	session, err := h.service.Callback(r.Context(), service.CallbackInput{
		Code: values.Get("code"), State: values.Get("state"), Binding: cookies[0].Value,
		UserAgent: httpx.UserAgent(r), IP: httpx.IP(r),
	})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	setFlowCookie(w, "")
	sessionhttp.SetSessionCookie(w, session.RawToken, session.ExpiresAt)
	httpx.JSON(w, 200, CallbackResponse{Status: "ok"})
}
