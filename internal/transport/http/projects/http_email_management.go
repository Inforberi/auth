package browser

import (
	"net/http"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/email/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/recovery/transport/http"
	projectaccount "github.com/Inforberi/financial-intelligence/internal/auth/project/account"
)

func (p *binding) emailManagementHandlers(handlers map[string]http.HandlerFunc, log *zap.Logger) {
	if p.Binding != nil {
		h := accountemailhttp.NewEmailBinding(projectaccount.ProjectBindingHTTP{ProjectEmail: p.Binding}, log)
		handlers["/api/v1/admin/users/{id}/email-binding"] = p.requireHTTPDelivery(h.Request)
	}
	if p.BindingConfirmation != nil {
		handlers["/api/v1/auth/email/binding/confirm"] = accountemailhttp.NewEmailBinding(projectaccount.ProjectBindingHTTP{ProjectEmail: p.BindingConfirmation}, log).Confirm
	}
	if p.Change != nil {
		h := accountemailhttp.NewEmailChange(projectaccount.ProjectChangeHTTP{ProjectEmail: p.Change}, log)
		handlers["/api/v1/auth/email/change"] = p.requireHTTPDelivery(h.Request)
	}
	if p.ChangeProtection != nil {
		h := accountemailhttp.NewEmailChange(projectaccount.ProjectChangeHTTP{ProjectEmail: p.ChangeProtection}, log)
		handlers["/api/v1/auth/email/change/confirm"], handlers["/api/v1/auth/email/change/report"] = h.Confirm, h.Report
		handlers["/api/v1/auth/email/change/recover"] = passwordrecoveryhttp.NewProtectedRecovery(projectaccount.ProjectProtectedRecoveryHTTP{ProjectEmail: p.ChangeProtection}, log).Recover
	}
}
