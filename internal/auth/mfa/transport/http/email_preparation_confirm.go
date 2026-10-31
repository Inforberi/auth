package mfahttp

import (
	"net/http"

	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type EmailPreparationConfirmation struct {
	Binding string `json:"binding"`
	Code    string `json:"code"`
} // @name mfa_http.EmailPreparationConfirmation

func (h *EmailHandler) ConfirmEmailPreparation(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	proof, ok := requestProof(w, r)
	if !ok {
		return
	}
	var input EmailPreparationConfirmation
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	result, err := h.preparation.Confirm(r.Context(), otpservice.EmailPreparationConfirmation{Proof: proof, Binding: input.Binding, Code: input.Code, IP: httpx.IP(r)})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	sessionhttp.SetSessionCookie(w, result.Token, result.ExpiresAt)
	httpx.JSON(w, 200, StatusResponse{Status: "ok"})
}
