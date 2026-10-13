package http

import (
	"net/http"

	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

const reauthenticationCookie = "__Host-email-reauthentication"

// @Summary Request an email proof for MFA management
// @Description Optional, existing external-only account with an active session and an already verified owned email. Does not attach or verify a new address, authenticate by password or issue a new session.
// @Tags MFA
// @Accept json
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Param body body RequestCodeRequest true "Already verified owned email"
// @Success 202 {object} StatusResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse "codes: invalid_origin, fresh_auth_required"
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/reauthenticate/email/request [post]
func (h *Handler) RequestReauthentication(w http.ResponseWriter, r *http.Request) {
	proof, ok := reauthenticationProof(w, r)
	if !ok {
		return
	}
	var input RequestCodeRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	result, err := h.service.RequestReauthentication(r.Context(), proof, input.Email, httpx.IP(r))
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	setNamedFlowCookie(w, reauthenticationCookie, result.Binding, result.ExpiresAt)
	httpx.JSON(w, 202, StatusResponse{Status: "accepted"})
}

func reauthenticationProof(w http.ResponseWriter, r *http.Request) (mfaservice.Proof, bool) {
	auth, ok := sessionhttp.GetAuthContext(r.Context())
	if !ok {
		httpx.Error(w, 401, "unauthorized", "unauthorized")
		return mfaservice.Proof{}, false
	}
	return mfaservice.Proof{UserID: auth.UserID, TokenHash: auth.TokenHash, AuthVersion: auth.AuthVersion}, true
}
