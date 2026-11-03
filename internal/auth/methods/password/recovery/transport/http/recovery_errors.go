package passwordrecoveryhttp

import (
	"net/http"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	passwordhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

var forgotErrors = []httpx.ErrorRule{
	httpx.MatchError(accountdomain.ErrEmailRequired, 400, "invalid_email", "invalid email"),
	httpx.MatchError(accountdomain.ErrEmailInvalid, 400, "invalid_email", "invalid email"),
	passwordhttp.RecoveryLimit(),
}

var resetErrors = []httpx.ErrorRule{
	passwordhttp.RecoveryLimit(),
	httpx.MatchError(domain.ErrInvalidReset, 400, "invalid_reset", "invalid reset"),
	httpx.MatchError(domain.ErrPasswordConfirmation, 400, "password_mismatch", "passwords do not match"),
	{Match: passwordhttp.PasswordPolicyError, Response: passwordhttp.PolicyFailure()},
}

func (h *RecoveryHandler) respondError(w http.ResponseWriter, r *http.Request, err error, operation string, rules []httpx.ErrorRule) {
	httpx.RespondError(w, r, h.log, operation, err, rules, passwordhttp.Unavailable())
}
