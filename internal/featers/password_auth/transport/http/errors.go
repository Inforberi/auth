package password_http

import (
	"errors"
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/core/transport/http/httpx"
	"go.uber.org/zap"
)

type errorBody struct {
	code    string
	message string
}

type clientError struct {
	err    error
	status int
	body   errorBody
}

type ErrorMapping struct {
	Status  int
	Code    string
	Message string
}

var (
	errInvalidJSON      = errorBody{"invalid_json", "invalid json"}
	errInternalError    = errorBody{"internal_error", "internal error"}
	errEmailRequired    = errorBody{"email_required", "email required"}
	errPasswordRequired = errorBody{"password_required", "password required"}
	errInvalidEmail     = errorBody{"invalid_email", "invalid email"}
)

func mapError(err error, clientErrors []clientError) ErrorMapping {
	for _, ce := range clientErrors {
		if errors.Is(err, ce.err) {
			return ErrorMapping{ce.status, ce.body.code, ce.body.message}
		}
	}

	return ErrorMapping{
		http.StatusInternalServerError,
		errInternalError.code,
		errInternalError.message,
	}
}

func (h *PasswordHandler) respondError(
	w http.ResponseWriter,
	r *http.Request,
	err error,
	operation string,
	clientErrors []clientError,
	logFields ...zap.Field,
) {
	mapped := mapError(err, clientErrors)

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
