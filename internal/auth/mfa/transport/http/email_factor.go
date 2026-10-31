package mfahttp

import (
	"net/http"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type EmailFactorResponse struct {
	Allowed     bool       `json:"allowed"`
	Configured  bool       `json:"configured"`
	Usable      bool       `json:"usable"`
	EmailID     string     `json:"emailId,omitempty"`
	EnabledAt   *time.Time `json:"enabledAt,omitempty"`
	SuspendedAt *time.Time `json:"suspendedAt,omitempty"`
} // @name mfa_http.EmailFactorResponse

func (h *EmailHandler) ReadEmailFactor(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	proof, ok := requestProof(w, r)
	if !ok {
		return
	}
	result, err := h.factors.Status(r.Context(), proof)
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, EmailFactorResponse{
		Allowed: result.Allowed, Configured: result.Configured, Usable: result.Usable,
		EmailID: string(result.EmailID), EnabledAt: result.EnabledAt, SuspendedAt: result.SuspendedAt,
	})
}
