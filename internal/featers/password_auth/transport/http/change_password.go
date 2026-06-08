package password_http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/core/transport/http/httpx"
)

var (
	errConfirmPassword = errorBody{"not_confirm_password", "password not confirmed"}
)

type ChangePasswordRequest struct {
	OldPassword     string `json:"oldPassword"`
	NewPassword     string `json:"newPassword"`
	ConfirmPassword string `json:"confirmPassword"`
}

func (p *PasswordHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	//TODO get userId and token from context from middleware

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

	// validate confirm password
	if input.NewPassword != input.ConfirmPassword {
		httpx.Error(
			w,
			http.StatusBadRequest,
			errConfirmPassword.code,
			errConfirmPassword.message,
		)
		return
	}

	// call service
	// p.service.ChangePassword(r.Context())

	// map error

}
