package password_http

import (
	"net/http"
)

type ChangePasswordRequest struct {
	OldPassword     string `json:"oldPassword"`
	NewPassword     string `json:"newPassword"`
	ConfirmPassword string `json:"confirmPassword"`
}

func (p *PasswordHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	// decode json
	// var input ChangePasswordRequest
	// if err := httpx.DecodeJSON(w, r, &input); err != nil {
	// 	httpx.Error(
	// 		w,
	// 		http.StatusBadRequest,
	// 		CodeInvalidJSON,
	// 		"invalid json",
	// 	)
	// }

	// // validate confirm password

	// // call service

	// // map error

}
