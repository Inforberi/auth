package http

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type protectedRecovery interface {
	Recover(context.Context, string, string, string, string) error
}

type ProtectedRecoveryHandler struct {
	service protectedRecovery
	log     *zap.Logger
}

func NewProtectedRecovery(service protectedRecovery, log *zap.Logger) *ProtectedRecoveryHandler {
	return &ProtectedRecoveryHandler{service: service, log: log}
}

type ProtectedRecoveryRequest struct {
	Token           string `json:"token"`
	NewPassword     string `json:"newPassword"`
	ConfirmPassword string `json:"confirmPassword"`
} // @name password_http.ProtectedRecoveryRequest

var protectedRecoveryErrors = []httpx.ErrorRule{
	recoveryLimit,
	httpx.MatchError(accountdomain.ErrInvalidAccountRecovery, 400, "invalid_account_recovery", "invalid account recovery"),
	httpx.MatchError(domain.ErrPasswordConfirmation, 400, "password_mismatch", "passwords do not match"),
	httpx.MatchError(domain.ErrSamePassword, 400, "same_password", "new password must be different"),
	{Match: passwordPolicyError, Response: passwordPolicyFailure},
}

// @Summary Recover an account after an unauthorized email change
// @Description Optional password-only profile. Distinct single-use token delivered to the old verified address after protective blocking. Atomically replaces the compromised password, restores that address, revokes access and invalidates previous protection links before activating the account. Does not bypass administrative blocking, create a session or run on GET.
// @Tags Auth
// @Accept json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Produce json
// @Param body body ProtectedRecoveryRequest true "recovery token and new password"
// @Success 200 {object} RecoveryResponse
// @Failure 400 {object} httpx.ErrorResponse "codes: invalid_json, invalid_account_recovery, password_mismatch, password_policy, same_password"
// @Failure 403 {object} httpx.ErrorResponse "code: invalid_origin"
// @Failure 429 {object} httpx.ErrorResponse "code: rate_limited"
// @Failure 503 {object} httpx.ErrorResponse "code: temporarily_unavailable"
// @Router /api/v1/auth/email/change/recover [post]
func (h *ProtectedRecoveryHandler) Recover(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var input ProtectedRecoveryRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	if err := h.service.Recover(r.Context(), input.Token, input.NewPassword, input.ConfirmPassword, httpx.IP(r)); err != nil {
		httpx.RespondError(w, r, h.log, "recover protected account", err, protectedRecoveryErrors, dependencyFailure)
		return
	}
	sessionhttp.ClearSessionCookie(w)
	httpx.JSON(w, 200, RecoveryResponse{Status: "ok"})
}
