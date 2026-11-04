package browser

import (
	"net/http"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/provisioning/transport/http"
	projectaccount "github.com/Inforberi/financial-intelligence/internal/auth/project/account"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/auth/project/methods"
)

func (p *binding) provisioningHandlers(handlers map[string]http.HandlerFunc, log *zap.Logger) {
	if p.Provisioning != nil {
		h := accountprovisioninghttp.NewProvisioning(projectaccount.ProjectProvisioningHTTP{ProjectEmail: p.Provisioning}, log)
		handlers["POST /api/v1/admin/users"] = p.requireHTTPDelivery(h.Provision)
		handlers["/api/v1/admin/users/{id}/invitation"] = p.requireHTTPDelivery(h.ReissueInvitation)
	}
	if p.Activation != nil {
		handlers["/api/v1/auth/invitations/activate"] = passwordprovisioninghttp.NewActivation(projectaccount.ProjectInvitationActivationHTTP{ProjectEmail: p.Activation}, log).Activate
	}
	if p.Available("temporary_password_admin") {
		h := passwordprovisioninghttp.NewTemporaryAdmin(projectmethods.ProjectTemporaryAdminHTTP{ProjectPassword: p.Password}, log)
		handlers["/api/v1/admin/users/temporary-password"], handlers["/api/v1/admin/users/{id}/temporary-password"] = h.Provision, h.Reissue
	}
}
