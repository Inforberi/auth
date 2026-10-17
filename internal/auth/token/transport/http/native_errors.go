package http

import (
	"errors"
	"net/http"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	emaildomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

var nativeErrors = append([]httpx.ErrorRule{
	httpx.MatchError(domain.ErrInvalidRefresh, 401, "invalid_refresh", "invalid refresh credential"),
	httpx.MatchError(domain.ErrRefreshLimit, 401, "login_required", "sign in again"),
	{Target: domain.ErrRefreshEarly, Response: httpx.Failure{Status: 429, Code: "refresh_too_early", Message: "refresh too early", Headers: http.Header{"Retry-After": {"30"}}}},
	httpx.MatchError(domain.ErrNativeDisabled, 404, "method_disabled", "login method disabled"),
	httpx.MatchError(passworddomain.ErrInvalidEmailOrPassword, 401, "invalid_credentials", "invalid email or password"),
	httpx.MatchError(passworddomain.ErrPasswordRequired, 400, "password_required", "password required"),
	httpx.MatchError(accountdomain.ErrEmailInvalid, 400, "invalid_email", "invalid email"),
	httpx.MatchError(accountdomain.ErrEmailRequired, 400, "invalid_email", "invalid email"),
	httpx.MatchError(emaildomain.ErrDisabled, 404, "method_disabled", "login method disabled"),
	httpx.MatchError(emaildomain.ErrInvalidCode, 400, "invalid_email_login", "invalid email login"),
	httpx.MatchError(mfadomain.ErrInvalidCode, 400, "invalid_mfa", "invalid MFA proof"),
	httpx.MatchError(mfadomain.ErrProofRequired, 401, "login_required", "sign in again"),
	httpx.MatchError(mfadomain.ErrConflict, 409, "mfa_conflict", "MFA state conflict"),
	{Target: emaildomain.ErrLimited, Response: httpx.Failure{Status: 429, Code: "rate_limited", Message: "rate limited", Headers: http.Header{"Retry-After": {"60"}}}},
	{Target: passworddomain.ErrLoginLimited, Response: httpx.Failure{Status: 429, Code: "rate_limited", Message: "rate limited", Headers: http.Header{"Retry-After": {"60"}}}},
	{Target: mfadomain.ErrLimited, Response: httpx.Failure{Status: 429, Code: "rate_limited", Message: "rate limited", Headers: http.Header{"Retry-After": {"60"}}}},
}, exchangeErrors...)

func (h *NativeHandler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, settingsdomain.ErrPolicyUnavailable) {
		w.Header().Set("Retry-After", "1")
	}
	if settingshttp.RespondPolicyError(w, r, h.log, err) {
		return
	}
	httpx.RespondError(w, r, h.log, "native_auth", err, nativeErrors, httpx.Failure{Status: 503, Code: "temporarily_unavailable", Message: "temporarily unavailable", Headers: http.Header{"Retry-After": {"1"}}})
}
