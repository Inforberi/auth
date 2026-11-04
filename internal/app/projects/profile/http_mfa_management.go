package profile

import (
	"net/http"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/management/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/recovery/transport/http"
)

func (p *ProjectProfile) mfaManagementHandlers(handlers map[string]http.HandlerFunc, log *zap.Logger) {
	if p.mfaRecovery != nil {
		h := mfarecoveryhttp.New(p.mfaRecovery, log)
		handlers["/api/v1/auth/mfa/recovery/start"] = p.requireHTTPDelivery(h.StartRecovery)
		handlers["/api/v1/auth/mfa/recovery/complete"] = p.requireHTTPDelivery(h.CompleteRecovery)
	}
	if p.mfaManagement == nil {
		return
	}
	h := mfamanagementhttp.New(p.mfaManagement, log)
	handlers["/api/v1/auth/mfa/status"] = h.ReadStatus
	handlers["/api/v1/auth/mfa/totp/enrollment"] = h.StartEnrollment
	handlers["/api/v1/auth/mfa/totp/enrollment/confirm"] = h.ConfirmEnrollment
	handlers["/api/v1/auth/mfa/step-up"] = h.StepUp
	handlers["/api/v1/auth/mfa/totp"] = h.Disable
	handlers["/api/v1/auth/mfa/recovery-codes/regenerate"] = h.RegenerateRecovery
	handlers["/api/v1/auth/mfa/totp/replacement"] = h.StartReplacement
	handlers["/api/v1/auth/mfa/totp/replacement/confirm"] = h.ConfirmReplacement
}
