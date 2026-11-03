package auth

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	accountprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/service"
	accountprovisioninghttp "github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/transport/http"
	passwordprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/provisioning/service"
	passwordprovisioninghttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/provisioning/transport/http"
)

func (p *ProjectProfile) provisioningHandlers(handlers map[string]http.HandlerFunc, log *zap.Logger) {
	if p.provisioning != nil {
		h := accountprovisioninghttp.NewProvisioning(projectProvisioningHTTP{p.provisioning}, log)
		handlers["POST /api/v1/admin/users"] = p.requireHTTPDelivery(h.Provision)
		handlers["/api/v1/admin/users/{id}/invitation"] = p.requireHTTPDelivery(h.ReissueInvitation)
	}
	if p.activation != nil {
		handlers["/api/v1/auth/invitations/activate"] = passwordprovisioninghttp.NewActivation(projectInvitationActivationHTTP{p.activation}, log).Activate
	}
	if p.featureReady("temporary_password_admin") {
		h := passwordprovisioninghttp.NewTemporaryAdmin(projectTemporaryAdminHTTP{p.password}, log)
		handlers["/api/v1/admin/users/temporary-password"], handlers["/api/v1/admin/users/{id}/temporary-password"] = h.Provision, h.Reissue
	}
}

type projectProvisioningHTTP struct{ *ProjectEmail }

func (s projectProvisioningHTTP) Provision(ctx context.Context, input accountprovisioning.ProvisionInput) (*accountprovisioning.ProvisionResult, error) {
	return s.ProvisionUser(ctx, input)
}

type projectInvitationActivationHTTP struct{ *ProjectEmail }

func (s projectInvitationActivationHTTP) Activate(ctx context.Context, token, password, confirmation, ip string) error {
	return s.ActivateInvitation(ctx, token, password, confirmation, ip)
}

type projectTemporaryAdminHTTP struct{ *ProjectPassword }

func (s projectTemporaryAdminHTTP) Provision(ctx context.Context, input passwordprovisioning.TemporaryProvisionInput) (*passwordprovisioning.TemporaryIssueResult, error) {
	return s.ProvisionTemporaryPassword(ctx, input)
}

func (s projectTemporaryAdminHTTP) Reissue(ctx context.Context, input passwordprovisioning.TemporaryReissueInput) (*passwordprovisioning.TemporaryIssueResult, error) {
	return s.ReissueTemporaryPassword(ctx, input)
}
