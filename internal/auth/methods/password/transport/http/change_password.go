package passwordhttp

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type ChangePasswordService interface {
	ChangePassword(context.Context, accountdomain.UserID, string, string, string) error
}

type ChangePasswordHandler struct {
	service  ChangePasswordService
	attempts passwordAttemptLimiter
	log      *zap.Logger
}

type passwordAttemptLimiter interface {
	AllowUser(context.Context, accountdomain.UserID, string) error
}

func NewChangePassword(service ChangePasswordService, attempts passwordAttemptLimiter, log *zap.Logger) *ChangePasswordHandler {
	return &ChangePasswordHandler{service: service, attempts: attempts, log: log}
}

type ChangePasswordRequest struct {
	OldPassword     string `json:"oldPassword" binding:"required" example:"ExamplePass1"`
	NewPassword     string `json:"newPassword" binding:"required" example:"ExamplePass2"`
	ConfirmPassword string `json:"confirmPassword" binding:"required" example:"ExamplePass2"`
} // @name password_http.ChangePasswordRequest

type ChangePasswordResponse struct {
	Status string `json:"Status" example:"ok"`
} // @name password_http.ChangePasswordResponse

func validateChangePasswordInput(input ChangePasswordRequest) error {
	switch {
	case input.OldPassword == "":
		return ErrEmptyOldPassword
	case input.NewPassword == "":
		return ErrEmptyNewPassword
	case input.ConfirmPassword == "":
		return ErrEmptyConfirmPassword
	case input.NewPassword != input.ConfirmPassword:
		return ErrPasswordMismatch
	}
	return nil
}

// @Summary change password
// @Description Requires a valid SQL-backed __Host-session, verified login email, allowed Origin and current password. Atomically updates password, revokes all sessions and records audit; sign in again. Response retains legacy uppercase Status. Existing role/MFA session requirements remain enforced.
// @Tags Auth
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Accept json
// @Produce json
// @Param body body ChangePasswordRequest true "change password payload"
// @Success 200 {object} ChangePasswordResponse
// @Failure 400 {object} httpx.ErrorResponse "codes: password_policy, invalid_json, password_mismatch, invalid_email_or_password, same_password, empty_new_password, empty_old_password, empty_confirm_password"
// @Failure 401 {object} httpx.ErrorResponse "code: unauthorized"
// @Failure 403 {object} httpx.ErrorResponse "codes: invalid_origin, email_not_verified"
// @Failure 429 {object} httpx.ErrorResponse "code: rate_limited"
// @Failure 503 {object} httpx.ErrorResponse "code: temporarily_unavailable"
// @Failure 404 {object} httpx.ErrorResponse "code: not_found"
// @Failure 500 {object} httpx.ErrorResponse "code: internal_error"
// @ID postAuthChangePassword
// @Router /api/v1/auth/change-password [post]
func (p *ChangePasswordHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	auth, ok := sessionhttp.GetAuthContext(r.Context())
	if !ok {
		httpx.Error(
			w,
			http.StatusUnauthorized,
			"unauthorized",
			"unauthorized",
		)
		return
	}

	var input ChangePasswordRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(
			w,
			http.StatusBadRequest,
			errInvalidJSON.code,
			errInvalidJSON.message,
		)
		return
	}

	if err := validateChangePasswordInput(input); err != nil {
		RespondPasswordError(w, r, p.log, err, "change password", changePasswordErrors)
		return
	}
	if p.attempts != nil {
		if err := p.attempts.AllowUser(r.Context(), auth.UserID, httpx.IP(r)); err != nil {
			RespondPasswordError(w, r, p.log, err, "change password", changePasswordErrors)
			return
		}
	}

	err := p.service.ChangePassword(
		r.Context(),
		auth.UserID,
		auth.TokenHash,
		input.OldPassword,
		input.NewPassword,
	)
	if err != nil {
		RespondPasswordError(w, r, p.log, err, "change password", changePasswordErrors)
		return
	}

	sessionhttp.ClearSessionCookie(w)
	httpx.JSON(
		w,
		http.StatusOK,
		ChangePasswordResponse{Status: "ok"},
	)
	p.log.Info("user change password")
}
