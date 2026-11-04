package account

import (
	"go.uber.org/zap"

	accountemail "github.com/Inforberi/financial-intelligence/internal/auth/account/email/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/email/transport/http"
	accountprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	passwordrecovery "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/recovery/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/recovery/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
)

type Management struct {
	Provisioning        *accountprovisioning.ProvisionService
	ProvisioningHandler *accountprovisioninghttp.ProvisioningHandler
	EmailChange         *accountemailhttp.EmailChangeHandler
	ProtectedRecovery   *passwordrecoveryhttp.ProtectedRecoveryHandler
}

func (a *App) AssembleManagement(hash *hasher.Bounded, recovery *passwordrecovery.RecoveryService, cfg *config.Config, log *zap.Logger) Management {
	var out Management
	if cfg.Invitation.Enabled {
		out.Provisioning = accountprovisioning.NewProvisioning(a.repository, a.limits, a.cipher, cfg.Invitation)
		out.ProvisioningHandler = accountprovisioninghttp.NewProvisioning(out.Provisioning, log)
	}
	if cfg.EmailChange.Enabled {
		svc := accountemail.NewEmailChange(a.repository, hash, a.limits, a.cipher, cfg.EmailChange, cfg.Session.FreshAuthTTL)
		out.EmailChange = accountemailhttp.NewEmailChange(svc, log)
		out.ProtectedRecovery = passwordrecoveryhttp.NewProtectedRecovery(passwordrecovery.NewProtectedRecovery(a.repository, recovery), log)
	}
	return out
}
