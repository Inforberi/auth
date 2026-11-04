package profile

import (
	"net/http"

	"go.uber.org/zap"

	projectaccount "github.com/Inforberi/financial-intelligence/internal/app/projects/account"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/email/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/recovery/transport/http"
)

func (p *ProjectProfile) emailManagementHandlers(handlers map[string]http.HandlerFunc, log *zap.Logger) {
	if p.binding != nil {
		h := accountemailhttp.NewEmailBinding(projectaccount.ProjectBindingHTTP{ProjectEmail: p.binding}, log)
		handlers["/api/v1/admin/users/{id}/email-binding"] = p.requireHTTPDelivery(h.Request)
	}
	if p.bindingConfirmation != nil {
		handlers["/api/v1/auth/email/binding/confirm"] = accountemailhttp.NewEmailBinding(projectaccount.ProjectBindingHTTP{ProjectEmail: p.bindingConfirmation}, log).Confirm
	}
	if p.change != nil {
		h := accountemailhttp.NewEmailChange(projectaccount.ProjectChangeHTTP{ProjectEmail: p.change}, log)
		handlers["/api/v1/auth/email/change"] = p.requireHTTPDelivery(h.Request)
	}
	if p.changeProtection != nil {
		h := accountemailhttp.NewEmailChange(projectaccount.ProjectChangeHTTP{ProjectEmail: p.changeProtection}, log)
		handlers["/api/v1/auth/email/change/confirm"], handlers["/api/v1/auth/email/change/report"] = h.Confirm, h.Report
		handlers["/api/v1/auth/email/change/recover"] = passwordrecoveryhttp.NewProtectedRecovery(projectaccount.ProjectProtectedRecoveryHTTP{ProjectEmail: p.changeProtection}, log).Recover
	}
}
