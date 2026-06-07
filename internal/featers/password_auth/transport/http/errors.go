package password_http

import (
	"errors"
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	"github.com/Inforberi/financial-intelligence/internal/core/transport/http/httpx"
	password_domain "github.com/Inforberi/financial-intelligence/internal/featers/password_auth/domain"
	"go.uber.org/zap"
)

type errorBody struct {
	code    string
	message string
}

// without map error
var (
	errInvalidJSON      = errorBody{"invalid_json", "invalid json"}
	errEmailRequired    = errorBody{"email_required", "email required"}
	errPasswordRequired = errorBody{"password_required", "password required"}
	errPasswordMismatch = errorBody{"password_mismatch", "passwords do not match"}
)

// with map error
var (
	// credentials
	errInvalidCredentials = errorBody{"invalid_credentials", "invalid email or password"}

	// user
	errUserNotFound = errorBody{"user_not_found", "user not found"}

	errNotFound = errorBody{"not_found", "user found"}

	// email
	errInvalidEmail = errorBody{"invalid_email", "invalid email"}
	errEmailExist   = errorBody{"email_exists", "email already exist"}

	// password
	errPasswordShort    = errorBody{"password_short", "password short"}
	errPasswordLong     = errorBody{"password_log", "password log"}
	errPasswordNoLetter = errorBody{"password_no_letter", "password need one letter"}
	errPasswordNoDigit  = errorBody{"password_no_digit", "password need one digit"}
	errPasswordNoUpper  = errorBody{"password_no_upper_letter", "password need one upper letter"}

	errInternalError = errorBody{"internal_error", "internal error"}
)

type clientError struct {
	err    error
	status int
	body   errorBody
}

var clientErrors = []clientError{
	// credentials
	{
		password_domain.ErrInvalidEmailOrPassword,
		http.StatusBadRequest,
		errInvalidCredentials,
	},
	{
		password_domain.ErrNotFound,
		http.StatusNotFound,
		errNotFound,
	},

	// email
	{
		domain.ErrEmailInvalid,
		http.StatusBadRequest,
		errInvalidEmail,
	},
	{
		password_domain.ErrEmailAlreadyExists,
		http.StatusConflict,
		errEmailExist,
	},

	// password
	{
		domain.ErrPasswordTooShort,
		http.StatusBadRequest,
		errPasswordShort,
	},
	{
		domain.ErrPasswordNoUpper,
		http.StatusBadRequest,
		errPasswordNoUpper,
	},
	{
		domain.ErrPasswordTooLong,
		http.StatusBadRequest,
		errPasswordLong,
	},
	{
		domain.ErrPasswordNoLetter,
		http.StatusBadRequest,
		errPasswordNoLetter,
	},
	{
		domain.ErrPasswordNoDigit,
		http.StatusBadRequest,
		errPasswordNoDigit,
	},
}

// internal
var internalError = ErrorMapping{
	http.StatusInternalServerError,
	errInternalError.code,
	errInternalError.message,
}

type ErrorMapping struct {
	Status  int
	Code    string
	Message string
}

func mapError(err error) ErrorMapping {
	for _, ce := range clientErrors {
		if errors.Is(err, ce.err) {
			return ErrorMapping{
				ce.status,
				ce.body.code,
				ce.body.message,
			}
		}
	}

	return ErrorMapping{
		internalError.Status,
		internalError.Code,
		internalError.Message,
	}
}

func (h *PasswordHandler) respondError(
	w http.ResponseWriter,
	r *http.Request,
	err error,
	operation string,
	logFields ...zap.Field,
) {
	mapped := mapError(err)

	fields := []zap.Field{
		zap.String("operation", operation),
		zap.String("ip", httpx.IP(r)),
		zap.String("user_agent", httpx.UserAgent(r)),
		zap.String("error_code", mapped.Code),
		zap.Int("status", mapped.Status),
		zap.Error(err),
	}

	fields = append(fields, logFields...)

	if mapped.Status >= 500 {
		h.log.Error(operation+" failed", fields...)
	} else {
		h.log.Warn(operation+" failed", fields...)
	}

	httpx.Error(w, mapped.Status, mapped.Code, mapped.Message)
}
