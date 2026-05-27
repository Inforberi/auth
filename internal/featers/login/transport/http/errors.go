package login_http

import (
	"errors"
	"net/http"

	login_domain "github.com/Inforberi/financial-intelligence/internal/featers/login/domain"
)

const (
	CodeInvalidJSON           = "invalid_json"
	CodeEmailRequired         = "email_required"
	CodePasswordRequired      = "password_required"
	CodeEmailPasswordRequired = "email_or_password_required"
	CodeNotFound              = "user_not_found"
	CodeInternalError         = "internal_error"
)

type ErrorMapping struct {
	Status  int
	Code    string
	Message string
}

func mapError(err error) ErrorMapping {
	switch {
	case errors.Is(err, login_domain.ErrInvalidEmailOrPassword):
		return ErrorMapping{
			Status:  http.StatusBadRequest,
			Code:    CodeEmailPasswordRequired,
			Message: "email or password required",
		}
	case errors.Is(err, login_domain.ErrNotFound):
		return ErrorMapping{
			Status:  http.StatusNotFound,
			Code:    CodeNotFound,
			Message: "user not found",
		}
	default:
		return ErrorMapping{
			Status:  http.StatusInternalServerError,
			Code:    CodeInternalError,
			Message: "internal server",
		}
	}
}
