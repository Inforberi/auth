package auth

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	passwordhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
)

func (p *ProjectProfile) provisioningHandlers(handlers map[string]http.HandlerFunc, log *zap.Logger) {
	if p.provisioning != nil {
		h := accounthttp.NewProvisioning(projectProvisioningHTTP{p.provisioning}, log)
		handlers["POST /api/v1/admin/users"] = p.requireHTTPDelivery(h.Provision)
		handlers["/api/v1/admin/users/{id}/invitation"] = p.requireHTTPDelivery(h.ReissueInvitation)
	}
	if p.activation != nil {
		handlers["/api/v1/auth/invitations/activate"] = passwordhttp.NewActivation(projectInvitationActivationHTTP{p.activation}, log).Activate
	}
	if p.featureReady("temporary_password_admin") {
		h := passwordhttp.NewTemporaryAdmin(projectTemporaryAdminHTTP{p.password}, log)
		handlers["/api/v1/admin/users/temporary-password"], handlers["/api/v1/admin/users/{id}/temporary-password"] = h.Provision, h.Reissue
	}
}

type projectProvisioningHTTP struct{ *ProjectEmail }

func (s projectProvisioningHTTP) Provision(ctx context.Context, input accountservice.ProvisionInput) (*accountservice.ProvisionResult, error) {
	return s.ProvisionUser(ctx, input)
}

type projectInvitationActivationHTTP struct{ *ProjectEmail }

func (s projectInvitationActivationHTTP) Activate(ctx context.Context, token, password, confirmation, ip string) error {
	return s.ActivateInvitation(ctx, token, password, confirmation, ip)
}

type projectTemporaryAdminHTTP struct{ *ProjectPassword }

func (s projectTemporaryAdminHTTP) Provision(ctx context.Context, input passwordservice.TemporaryProvisionInput) (*passwordservice.TemporaryIssueResult, error) {
	return s.ProvisionTemporaryPassword(ctx, input)
}

func (s projectTemporaryAdminHTTP) Reissue(ctx context.Context, input passwordservice.TemporaryReissueInput) (*passwordservice.TemporaryIssueResult, error) {
	return s.ReissueTemporaryPassword(ctx, input)
}
