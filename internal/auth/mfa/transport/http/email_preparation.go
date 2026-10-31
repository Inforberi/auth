package mfahttp

import (
	"net/http"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type EmailPreparationRequest struct {
	Email string `json:"email"`
} // @name mfa_http.EmailPreparationRequest

type EmailPreparationResponse struct {
	Binding   string    `json:"binding"`
	ExpiresAt time.Time `json:"expiresAt"`
} // @name mfa_http.EmailPreparationResponse

func (h *EmailHandler) RequestEmailPreparation(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	proof, ok := requestProof(w, r)
	if !ok {
		return
	}
	var input EmailPreparationRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	result, err := h.preparation.Request(r.Context(), proof, input.Email, httpx.IP(r))
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 202, EmailPreparationResponse{Binding: result.Binding, ExpiresAt: result.ExpiresAt})
}
