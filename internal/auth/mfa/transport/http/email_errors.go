package mfahttp

import (
	"net/http"

	"go.uber.org/zap"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	otpdomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

var emailErrors = append([]httpx.ErrorRule{
	httpx.MatchError(accountdomain.ErrEmailRequired, 400, "email_required", "email required"),
	httpx.MatchError(accountdomain.ErrEmailInvalid, 400, "invalid_email", "invalid email"),
	httpx.MatchError(passworddomain.ErrInvalidEmail, 400, "invalid_email", "invalid email"),
	httpx.MatchError(passworddomain.ErrPasswordRequired, 400, "password_required", "password required"),
	httpx.MatchError(passworddomain.ErrInvalidEmailOrPassword, 400, "invalid_credentials", "invalid credentials"),
	httpx.MatchError(passworddomain.ErrLoginUnavailable, 503, "temporarily_unavailable", "temporarily unavailable"),
	httpx.MatchError(passworddomain.ErrHashBusy, 503, "temporarily_unavailable", "temporarily unavailable"),
	httpx.MatchError(otpdomain.ErrInvalidPreparation, 400, "invalid_email_factor", "invalid email factor proof"),
	{Target: otpdomain.ErrLimited, Response: httpx.Failure{Status: 429, Code: "rate_limited", Message: "rate limited", Headers: http.Header{"Retry-After": {"60"}}}},
	{Target: passworddomain.ErrLoginLimited, Response: httpx.Failure{Status: 429, Code: "rate_limited", Message: "rate limited", Headers: http.Header{"Retry-After": {"60"}}}},
}, mfaErrors...)

func RespondEmailError(w http.ResponseWriter, r *http.Request, log *zap.Logger, err error) {
	respondError(w, r, log, err, emailErrors)
}
