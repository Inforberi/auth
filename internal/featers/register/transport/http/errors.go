package register_http

import (
	"errors"
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	register_service "github.com/Inforberi/financial-intelligence/internal/featers/register/service"
)

const (
	CodeInvalidJSON         = "invalid_json"
	CodeEmailRequired       = "email_required"
	CodePasswordRequired    = "password_required"
	CodeInvalidEmail        = "invalid_email"
	CodePasswordTooShort    = "password_too_short"
	CodePasswordTooLong     = "password_too_long"
	CodePasswordNoLetter    = "password_no_letter"
	CodePasswordNoDigit     = "password_no_digit"
	CodePasswordNoUppercase = "password_no_upper_letter"
	CodeEmailAlreadyExists  = "email_already_exists"
	CodeInternalError       = "internal_error"
)

type ErrorMapping struct {
	Status  int
	Code    string
	Message string
}

func mapError(err error) ErrorMapping {

	switch {
	case errors.Is(err, domain.ErrEmailInvalid):
		return ErrorMapping{
			Status:  http.StatusBadRequest,
			Code:    CodeInvalidEmail,
			Message: "Invalid email",
		}
	case errors.Is(err, register_service.ErrEmailAlreadyExists):
		return ErrorMapping{
			Status:  http.StatusConflict,
			Code:    CodeEmailAlreadyExists,
			Message: "Email already exists",
		}
	case errors.Is(err, domain.ErrPasswordTooShort):
		return ErrorMapping{
			Status:  http.StatusBadRequest,
			Code:    CodePasswordTooShort,
			Message: "Password too short",
		}
	case errors.Is(err, domain.ErrPasswordNoUpper):
		return ErrorMapping{
			Status:  http.StatusBadRequest,
			Code:    CodePasswordNoUppercase,
			Message: "Password must contain at least one uppercase letter",
		}
	case errors.Is(err, domain.ErrPasswordTooLong):
		return ErrorMapping{
			Status:  http.StatusBadRequest,
			Code:    CodePasswordTooLong,
			Message: "Password too long",
		}
	case errors.Is(err, domain.ErrPasswordNoLetter):
		return ErrorMapping{
			Status:  http.StatusBadRequest,
			Code:    CodePasswordNoLetter,
			Message: "Password must contain at least one letter",
		}
	case errors.Is(err, domain.ErrPasswordNoDigit):
		return ErrorMapping{
			Status:  http.StatusBadRequest,
			Code:    CodePasswordNoDigit,
			Message: "Password must contain at least one digit",
		}
	default:
		return ErrorMapping{
			Status:  http.StatusInternalServerError,
			Code:    CodeInternalError,
			Message: "Internal error",
		}
	}

}
