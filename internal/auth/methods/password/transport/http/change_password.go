package http

import (
	"net/http"

	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

// @Summary change password
// @Description change password
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body ChangePasswordRequest true "change password payload"
// @Success 200 {object} ChangePasswordResponse
// @Failure 400 {object} httpx.ErrorResponse "codes: invalid_json, password_mismatch, invalid_email_or_password, same_password, empty_new_password, empty_old_password, empty_confirm_password"
// @Failure 401 {object} httpx.ErrorResponse "code: unauthorized"
// @Failure 404 {object} httpx.ErrorResponse "code: not_found"
// @Failure 500 {object} httpx.ErrorResponse "code: internal_error"
// @Router /api/v1/auth/change-password [post]
func (p *PasswordHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
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
		p.respondError(w, r, err, "change password", changePasswordErrors)
		return
	}

	err := p.service.ChangePassword(
		r.Context(),
		auth.UserID,
		auth.TokenHash,
		input.OldPassword,
		input.NewPassword,
	)
	if err != nil {
		p.respondError(w, r, err, "change password", changePasswordErrors)
		return
	}

	httpx.JSON(
		w,
		http.StatusOK,
		ChangePasswordResponse{Status: "ok"},
	)
	p.log.Info("user change password")
}
