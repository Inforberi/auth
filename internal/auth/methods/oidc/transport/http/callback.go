package oidchttp

import (
	"net/http"
	"net/url"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type CallbackResponse struct {
	Status string `json:"status"`
}

func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(values["code"]) != 1 || len(values["state"]) != 1 || len(values["error"]) != 0 {
		h.respondError(w, r, domain.ErrInvalidFlow)
		return
	}
	cookies := r.CookiesNamed(h.cookie)
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
	h.setFlowCookie(w, "")
	if !result.Linked {
		sessionhttp.SetSessionCookie(w, result.Session.RawToken, result.Session.ExpiresAt)
	}
	httpx.JSON(w, 200, CallbackResponse{Status: "ok"})
}
