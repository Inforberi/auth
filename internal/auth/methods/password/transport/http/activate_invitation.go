package http

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type activationService interface {
	Activate(context.Context, string, string, string, string) error
}

type ActivationHandler struct {
	service activationService
	log     *zap.Logger
}

func NewActivation(service activationService, log *zap.Logger) *ActivationHandler {
	return &ActivationHandler{service: service, log: log}
}

type ActivationRequest struct {
	Token           string `json:"token"`
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirmPassword"`
} // @name password_http.ActivationRequest

var activationErrors = []httpx.ErrorRule{
	httpx.MatchError(accountdomain.ErrInvalidInvitation, 400, "invalid_invitation", "invalid invitation"),
	httpx.MatchError(domain.ErrPasswordConfirmation, 400, "password_mismatch", "passwords do not match"),
	{Match: passwordPolicyError, Response: passwordPolicyFailure},
	{Target: domain.ErrRecoveryLimited, Response: httpx.Failure{Status: 429, Code: "rate_limited", Message: "rate limited", Headers: http.Header{"Retry-After": {"60"}}}},
}

// @Summary Activate an invited password account
// @Description Optional invitation profile. Consumes a distinct one-time token, sets a password and verifies the invited contact atomically. Expired, replayed, blocked and unknown tokens have one error. Does not create a session or assign roles. GET never activates an account.
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body ActivationRequest true "invitation token and password"
// @Success 200 {object} RecoveryResponse
// @Failure 400 {object} httpx.ErrorResponse "codes: invalid_json, invalid_invitation, password_mismatch, password_policy"
// @Failure 403 {object} httpx.ErrorResponse "code: invalid_origin"
// @Failure 429 {object} httpx.ErrorResponse "code: rate_limited"
// @Failure 503 {object} httpx.ErrorResponse "code: temporarily_unavailable"
// @Router /api/v1/auth/invitations/activate [post]
func (h *ActivationHandler) Activate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var input ActivationRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	if err := h.service.Activate(r.Context(), input.Token, input.Password, input.ConfirmPassword, httpx.IP(r)); err != nil {
		httpx.RespondError(w, r, h.log, "activate invitation", err, activationErrors, dependencyFailure)
		return
	}
	httpx.JSON(w, 200, RecoveryResponse{Status: "ok"})
}
