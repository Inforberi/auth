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

// @Summary Read personal email MFA status
// @Description Current owner session only. Does not refresh its lifetime or reveal another user. Configured, usable and suspended are distinct states.
// @Tags MFA
// @Produce json
// @Success 200 {object} EmailFactorResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/mfa/email [get]
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
