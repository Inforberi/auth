package mfarecoveryhttp

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	mfaloginhttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/transport/http"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type (
	recoveryPrimaryStarter interface {
		Start(context.Context, mfaservice.PrimaryProof, string) (*mfalogin.LoginChallenge, error)
	}
	RecoveryLoginHandler struct {
		password mfahttp.Password
		starter  recoveryPrimaryStarter
		log      *zap.Logger
	}
)

func NewRecoveryLogin(password mfahttp.Password, starter recoveryPrimaryStarter, log *zap.Logger) *RecoveryLoginHandler {
	return &RecoveryLoginHandler{password: password, starter: starter, log: log}
}

// @Summary Explicitly request MFA recovery after password verification
// @Description Does not authenticate or bypass a factor. Creates a primary-bound challenge for the existing independently approved recovery process; no delivery fallback.
// @Tags MFA
// @Accept json
// @Produce json
// @Param body body mfaloginhttp.EmailLoginRequest true "primary credentials"
// @Success 202 {object} mfaloginhttp.ChallengeResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @ID postAuthMfaRecoveryLogin
// @Router /api/v1/auth/mfa/recovery/login [post]
func (h *RecoveryLoginHandler) Start(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var input mfaloginhttp.EmailLoginRequest
	if httpx.DecodeJSON(w, r, &input) != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	proof, err := h.password.Authenticate(r.Context(), passwordservice.LoginInput{Email: input.Email, Password: input.Password, UserAgent: httpx.UserAgent(r), IP: httpx.IP(r)})
	if err != nil {
		mfahttp.RespondEmailError(w, r, h.log, err)
		return
	}
	result, err := h.starter.Start(r.Context(), proof, httpx.IP(r))
	if err != nil {
		mfahttp.RespondEmailError(w, r, h.log, err)
		return
	}
	mfaloginhttp.RespondChallenge(w, result)
}
