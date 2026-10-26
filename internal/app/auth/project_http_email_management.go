package auth

import (
	"context"
	"net/http"
	"time"

	"go.uber.org/zap"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
	passwordhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (p *ProjectProfile) emailManagementHandlers(handlers map[string]http.HandlerFunc, log *zap.Logger) {
	if p.binding != nil {
		h := accounthttp.NewEmailBinding(projectBindingHTTP{p.binding}, log)
		handlers["/api/v1/admin/users/{id}/email-binding"] = p.requireHTTPDelivery(h.Request)
	}
	if p.bindingConfirmation != nil {
		handlers["/api/v1/auth/email/binding/confirm"] = accounthttp.NewEmailBinding(projectBindingHTTP{p.bindingConfirmation}, log).Confirm
	}
	if p.change != nil {
		h := accounthttp.NewEmailChange(projectChangeHTTP{p.change}, log)
		handlers["/api/v1/auth/email/change"] = p.requireHTTPDelivery(h.Request)
	}
	if p.changeProtection != nil {
		h := accounthttp.NewEmailChange(projectChangeHTTP{p.changeProtection}, log)
		handlers["/api/v1/auth/email/change/confirm"], handlers["/api/v1/auth/email/change/report"] = h.Confirm, h.Report
		handlers["/api/v1/auth/email/change/recover"] = passwordhttp.NewProtectedRecovery(projectProtectedRecoveryHTTP{p.changeProtection}, log).Recover
	}
}

type projectBindingHTTP struct{ *ProjectEmail }

func (s projectBindingHTTP) Request(ctx context.Context, input accountservice.EmailBindingInput) (time.Time, error) {
	return s.RequestEmailBinding(ctx, input)
}

func (s projectBindingHTTP) Confirm(ctx context.Context, proof mfaservice.Proof, code, ip string) error {
	return s.ConfirmEmailBinding(ctx, proof, code, ip)
}

type projectChangeHTTP struct{ *ProjectEmail }

func (s projectChangeHTTP) Request(ctx context.Context, user accountdomain.UserID, hash, email, password, ip string) error {
	return s.RequestEmailChange(ctx, user, hash, email, password, ip)
}

func (s projectChangeHTTP) Confirm(ctx context.Context, token, ip string) error {
	return s.ConfirmEmailChange(ctx, token, ip)
}

func (s projectChangeHTTP) Report(ctx context.Context, token, ip string) error {
	return s.ReportEmailChange(ctx, token, ip)
}

type projectProtectedRecoveryHTTP struct{ *ProjectEmail }

func (s projectProtectedRecoveryHTTP) Recover(ctx context.Context, token, password, confirmation, ip string) error {
	return s.RecoverEmailChange(ctx, token, password, confirmation, ip)
}
