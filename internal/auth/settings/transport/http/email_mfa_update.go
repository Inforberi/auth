package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type EmailMFAUpdateRequest struct {
	ExpectedVersion int64 `json:"expectedVersion"`
	Allowed         *bool `json:"allowed"`
} // @name mfa_settings_http.EmailUpdateRequest

func (h *EmailMFAHandler) Update(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := principal(w, r)
	if !ok {
		return
	}
	var input EmailMFAUpdateRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil || input.Allowed == nil {
		httpx.Error(w, 400, "invalid_json", "complete email MFA configuration required")
		return
	}
	result, err := h.service.Update(r.Context(), service.EmailMFAUpdate{Actor: actor, ExpectedVersion: input.ExpectedVersion, Allowed: *input.Allowed})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	h.respond(w, result)
}
