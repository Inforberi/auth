package http

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type temporaryPasswordService interface {
	Login(context.Context, string, string, string) (*service.TemporaryLoginResult, error)
	Complete(context.Context, string, string, string, string) error
}

type TemporaryPasswordHandler struct {
	service temporaryPasswordService
	log     *zap.Logger
}

func NewTemporaryPassword(service temporaryPasswordService, log *zap.Logger) *TemporaryPasswordHandler {
	return &TemporaryPasswordHandler{service: service, log: log}
}

var temporaryPasswordErrors = append([]httpx.ErrorRule{
	httpx.MatchError(domain.ErrInvalidTemporaryPassword, 400, "invalid_temporary_password", "invalid temporary password authority"),
	httpx.MatchError(domain.ErrTemporaryPasswordReuse, 400, "same_password", "new password must differ from temporary password"),
	httpx.MatchError(domain.ErrPasswordConfirmation, 400, "password_mismatch", "passwords do not match"),
	{Match: passwordPolicyError, Response: passwordPolicyFailure},
	{Target: domain.ErrRecoveryLimited, Response: httpx.Failure{Status: 429, Code: "rate_limited", Message: "rate limited", Headers: http.Header{"Retry-After": {"60"}}}},
	{Target: domain.ErrLoginLimited, Response: httpx.Failure{Status: 429, Code: "rate_limited", Message: "rate limited", Headers: http.Header{"Retry-After": {"60"}}}},
}, loginClientErrors...)
