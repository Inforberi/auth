package profile

import (
	"net/http"

	"go.uber.org/zap"

	projectaccount "github.com/Inforberi/financial-intelligence/internal/app/projects/account"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/app/projects/methods"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/provisioning/transport/http"
)

func (p *ProjectProfile) provisioningHandlers(handlers map[string]http.HandlerFunc, log *zap.Logger) {
	if p.provisioning != nil {
		h := accountprovisioninghttp.NewProvisioning(projectaccount.ProjectProvisioningHTTP{ProjectEmail: p.provisioning}, log)
		handlers["POST /api/v1/admin/users"] = p.requireHTTPDelivery(h.Provision)
		handlers["/api/v1/admin/users/{id}/invitation"] = p.requireHTTPDelivery(h.ReissueInvitation)
	}
	if p.activation != nil {
		handlers["/api/v1/auth/invitations/activate"] = passwordprovisioninghttp.NewActivation(projectaccount.ProjectInvitationActivationHTTP{ProjectEmail: p.activation}, log).Activate
	}
	if p.featureReady("temporary_password_admin") {
		h := passwordprovisioninghttp.NewTemporaryAdmin(projectmethods.ProjectTemporaryAdminHTTP{ProjectPassword: p.password}, log)
		handlers["/api/v1/admin/users/temporary-password"], handlers["/api/v1/admin/users/{id}/temporary-password"] = h.Provision, h.Reissue
	}
}
