package password_http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/core/transport/http/httpx"
	password_domain "github.com/Inforberi/financial-intelligence/internal/featers/password_auth/domain"
)

var (
	errConfirmPassword        = errorBody{"not_confirm_password", "password not confirmed"}
	errInvalidEmailOrPassword = errorBody{"invalid_email_or_password", "invalid email or password"}
	errSamePassword           = errorBody{"same_password", "same password"}
	errNotFound               = errorBody{"not_found", "not found"}
)

var changePasswordErrors = []clientError{
	{
		password_domain.ErrInvalidEmailOrPassword,
		http.StatusBadRequest,
		errInvalidEmailOrPassword,
	},
	{
		password_domain.ErrSamePassword,
		http.StatusBadRequest,
		errSamePassword,
	},
	{
		password_domain.ErrNotFound,
		http.StatusNotFound,
		errNotFound,
	},
}

type ChangePasswordRequest struct {
	OldPassword     string `json:"oldPassword"`
	NewPassword     string `json:"newPassword"`
	ConfirmPassword string `json:"confirmPassword"`
}

type ChangePasswordResponse struct {
	Status string
}

func (p *PasswordHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	auth, ok := httpx.GetAuthContext(r.Context())
	if !ok {
		panic("get auth form context")
	}

	// decode json
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

	if input.NewPassword == "" {
		httpx.Error(
			w,
			http.StatusBadRequest,
			"empty_new_password",
			"new password cannot be empty",
		)
		return
	}

	if input.ConfirmPassword == "" {
		httpx.Error(
			w,
			http.StatusBadRequest,
			"empty_confirm_password",
			"confirmation password cannot be empty",
		)
		return
	}

	if input.NewPassword != input.ConfirmPassword {
		httpx.Error(
			w,
			http.StatusBadRequest,
			"password_mismatch",
			"new password and confirmation do not match",
		)
		return
	}

	// call service
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
