package http

import (
	"context"
	"errors"
	"net/http"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type errorBody struct {
	code    string
	message string
}

var (
	errInvalidJSON      = errorBody{"invalid_json", "invalid json"}
	errInternalError    = errorBody{"internal_error", "internal error"}
	errEmailRequired    = errorBody{"email_required", "email required"}
	errPasswordRequired = errorBody{"password_required", "password required"}
	errInvalidEmail     = errorBody{"invalid_email", "invalid email"}
	errNotFound         = errorBody{"not_found", "not found"}
)

var (
	errEmailAlreadyExists = errorBody{"email_already_exists", "email already exists"}
	errPasswordTooShort   = errorBody{"password_too_short", "password too short"}
	errPasswordTooLong    = errorBody{"password_too_long", "password too long"}
	errPasswordNoLetter   = errorBody{"password_no_letter", "password must contain at least one letter"}
	errPasswordNoDigit    = errorBody{"password_no_digit", "password must contain at least one digit"}
	errPasswordNoUpper    = errorBody{"password_no_upper_letter", "password must contain at least one uppercase letter"}
)

var errInvalidCredentials = errorBody{"invalid_credentials", "invalid email or password"}

var (
	errConfirmPassword        = errorBody{"password_mismatch", "passwords do not match"}
	errInvalidEmailOrPassword = errorBody{"invalid_email_or_password", "invalid email or password"}
	errSamePassword           = errorBody{"same_password", "same password"}
	errEmptyNewPassword       = errorBody{"empty_new_password", "new password cannot be empty"}
	errEmptyOldPassword       = errorBody{"empty_old_password", "old password cannot be empty"}
	errEmptyConfirmPassword   = errorBody{"empty_confirm_password", "confirmation password cannot be empty"}
)

var (
	ErrEmptyOldPassword     = errors.New("empty_old_password")
	ErrEmptyNewPassword     = errors.New("empty_new_password")
	ErrEmptyConfirmPassword = errors.New("empty_confirm_password")
	ErrPasswordMismatch     = errors.New("password_mismatch")
)

var (
	internalFailure       = httpx.Failure{Status: 500, Code: "internal_error", Message: "internal error"}
	dependencyFailure     = httpx.Failure{Status: 503, Code: "temporarily_unavailable", Message: "temporarily unavailable"}
	passwordPolicyFailure = httpx.Failure{Status: 400, Code: "password_policy", Message: "invalid password"}
)

var registerClientErrors = []httpx.ErrorRule{
	httpx.MatchError(passworddomain.ErrPasswordRequired, 400, errPasswordRequired.code, errPasswordRequired.message),
	httpx.MatchError(accountdomain.ErrEmailInvalid, http.StatusBadRequest, errInvalidEmail.code, errInvalidEmail.message),
	httpx.MatchError(accountdomain.ErrEmailRequired, http.StatusBadRequest, errEmailRequired.code, errEmailRequired.message),
	httpx.MatchError(passworddomain.ErrEmailAlreadyExists, http.StatusConflict, errEmailAlreadyExists.code, errEmailAlreadyExists.message),
	httpx.MatchError(passworddomain.ErrPasswordTooShort, http.StatusBadRequest, errPasswordTooShort.code, errPasswordTooShort.message),
	httpx.MatchError(passworddomain.ErrPasswordTooLong, http.StatusBadRequest, errPasswordTooLong.code, errPasswordTooLong.message),
	httpx.MatchError(passworddomain.ErrPasswordNoLetter, http.StatusBadRequest, errPasswordNoLetter.code, errPasswordNoLetter.message),
	httpx.MatchError(passworddomain.ErrPasswordNoDigit, http.StatusBadRequest, errPasswordNoDigit.code, errPasswordNoDigit.message),
	httpx.MatchError(passworddomain.ErrPasswordNoUpper, http.StatusBadRequest, errPasswordNoUpper.code, errPasswordNoUpper.message),
}

var loginClientErrors = []httpx.ErrorRule{
	httpx.MatchError(accountdomain.ErrEmailRequired, 400, errEmailRequired.code, errEmailRequired.message),
	httpx.MatchError(passworddomain.ErrPasswordRequired, 400, errPasswordRequired.code, errPasswordRequired.message),
	httpx.MatchError(passworddomain.ErrInvalidEmailOrPassword, http.StatusBadRequest, errInvalidCredentials.code, errInvalidCredentials.message),
	httpx.MatchError(accountdomain.ErrEmailInvalid, http.StatusBadRequest, errInvalidEmail.code, errInvalidEmail.message),
}

var changePasswordErrors = []httpx.ErrorRule{
	{Match: passwordPolicyError, Response: passwordPolicyFailure},
	httpx.MatchError(passworddomain.ErrInvalidEmailOrPassword, http.StatusBadRequest, errInvalidEmailOrPassword.code, errInvalidEmailOrPassword.message),
	httpx.MatchError(passworddomain.ErrSamePassword, http.StatusBadRequest, errSamePassword.code, errSamePassword.message),
	httpx.MatchError(passworddomain.ErrNotFound, http.StatusNotFound, errNotFound.code, errNotFound.message),
	httpx.MatchError(ErrEmptyNewPassword, http.StatusBadRequest, errEmptyNewPassword.code, errEmptyNewPassword.message),
	httpx.MatchError(ErrEmptyOldPassword, http.StatusBadRequest, errEmptyOldPassword.code, errEmptyOldPassword.message),
	httpx.MatchError(ErrEmptyConfirmPassword, http.StatusBadRequest, errEmptyConfirmPassword.code, errEmptyConfirmPassword.message),
	httpx.MatchError(ErrPasswordMismatch, http.StatusBadRequest, errConfirmPassword.code, errConfirmPassword.message),
}

func (h *PasswordHandler) respondError(w http.ResponseWriter, r *http.Request, err error, operation string, rules []httpx.ErrorRule) {
	if settingshttp.RespondPolicyError(w, r, h.log, err) {
		return
	}
	if failure := httpx.MapError(err, capacityErrors, httpx.Failure{}); failure.Status != 0 {
		httpx.RespondError(w, r, h.log, operation, err, nil, failure)
		return
	}
	httpx.RespondError(w, r, h.log, operation, err, rules, internalFailure)
}

var capacityErrors = []httpx.ErrorRule{
	{Target: passworddomain.ErrHashBusy, Response: dependencyFailure},
	{Target: passworddomain.ErrLoginUnavailable, Response: dependencyFailure},
	{Target: context.DeadlineExceeded, Response: dependencyFailure},
	{Target: context.Canceled, Response: dependencyFailure},
	{Target: passworddomain.ErrLoginLimited, Response: httpx.Failure{Status: 429, Code: "rate_limited", Message: "rate limited", Headers: http.Header{"Retry-After": {"60"}}}},
}

func passwordPolicyError(err error) bool {
	return errors.Is(err, passworddomain.ErrPasswordTooShort) ||
		errors.Is(err, passworddomain.ErrPasswordTooLong) ||
		errors.Is(err, passworddomain.ErrPasswordNoLetter) ||
		errors.Is(err, passworddomain.ErrPasswordNoDigit) ||
		errors.Is(err, passworddomain.ErrPasswordNoUpper)
}
