package mfahttp

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type SecurityStatusResponse struct {
	TOTPEnabled                  bool `json:"totpEnabled"`
	RequiredByRole               bool `json:"requiredByRole"`
	RequiredByAdministration     bool `json:"requiredByAdministration"`
	DisableAllowedByPolicy       bool `json:"disableAllowedByPolicy"`
	RecoveryCodesRemaining       int  `json:"recoveryCodesRemaining"`
	VerifiedEmail                bool `json:"verifiedEmail"`
	PasswordConfigured           bool `json:"passwordConfigured"`
	EmailReauthenticationEnabled bool `json:"emailReauthenticationEnabled"`
	FreshPrimaryProof            bool `json:"freshPrimaryProof"`
	FreshMFAProof                bool `json:"freshMfaProof"`
} // @name mfa_http.SecurityStatusResponse

// @Summary Read own MFA status and policy
// @Description Live owner-only snapshot, no fresh proof required. No secrets, recovery code values, session refresh or audit. Availability is local, not SMTP/fleet health. Policy flags are informational; mutations independently recheck current state and proof.
// @Tags MFA
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Success 200 {object} SecurityStatusResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/mfa/status [get]
func (h *Handler) ReadStatus(w http.ResponseWriter, r *http.Request) {
	proof, ok := requestProof(w, r)
	if !ok {
		return
	}
	status, err := h.management.Status(r.Context(), proof)
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.JSON(w, 200, SecurityStatusResponse{
		TOTPEnabled: status.TOTPEnabled, RequiredByRole: status.RequiredByRole,
		RequiredByAdministration: status.RequiredByAdministration,
		DisableAllowedByPolicy:   status.TOTPEnabled && !status.RequiredByRole && !status.RequiredByAdministration,
		RecoveryCodesRemaining:   status.RecoveryCodesRemaining, VerifiedEmail: status.VerifiedEmail,
		PasswordConfigured: status.PasswordConfigured, EmailReauthenticationEnabled: status.EmailReauthenticationEnabled,
		FreshPrimaryProof: status.FreshPrimaryProof, FreshMFAProof: status.FreshMFAProof,
	})
}
