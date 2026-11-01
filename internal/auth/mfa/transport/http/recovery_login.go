package mfahttp

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type (
	recoveryPrimaryStarter interface {
		Start(context.Context, service.PrimaryProof, string) (*service.LoginChallenge, error)
	}
	RecoveryLoginHandler struct {
		password emailPassword
		starter  recoveryPrimaryStarter
		log      *zap.Logger
	}
)

func NewRecoveryLogin(password emailPassword, starter recoveryPrimaryStarter, log *zap.Logger) *RecoveryLoginHandler {
	return &RecoveryLoginHandler{password: password, starter: starter, log: log}
}

// @Summary Explicitly request MFA recovery after password verification
// @Description Does not authenticate or bypass a factor. Creates a primary-bound challenge for the existing independently approved recovery process; no delivery fallback.
// @Tags MFA
// @Accept json
// @Produce json
// @Param body body EmailLoginRequest true "primary credentials"
// @Success 202 {object} ChallengeResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Router /api/v1/auth/mfa/recovery/login [post]
func (h *RecoveryLoginHandler) Start(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var input EmailLoginRequest
	if httpx.DecodeJSON(w, r, &input) != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	proof, err := h.password.Authenticate(r.Context(), passwordservice.LoginInput{Email: input.Email, Password: input.Password, UserAgent: httpx.UserAgent(r), IP: httpx.IP(r)})
	if err != nil {
		respondMFAError(w, r, h.log, err, emailMFAErrors)
		return
	}
	result, err := h.starter.Start(r.Context(), proof, httpx.IP(r))
	if err != nil {
		respondMFAError(w, r, h.log, err, emailMFAErrors)
		return
	}
	RespondChallenge(w, result)
}
