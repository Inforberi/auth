package auth

import (
	"net/http"

	"go.uber.org/zap"

	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
)

func (p *ProjectProfile) mfaManagementHandlers(handlers map[string]http.HandlerFunc, log *zap.Logger) {
	if p.mfaManagement == nil {
		return
	}
	h := mfahttp.New(p.mfaManagement, nil, log)
	handlers["/api/v1/auth/mfa/status"] = h.ReadStatus
	handlers["/api/v1/auth/mfa/totp/enrollment"] = h.StartEnrollment
	handlers["/api/v1/auth/mfa/totp/enrollment/confirm"] = h.ConfirmEnrollment
	handlers["/api/v1/auth/mfa/step-up"] = h.StepUp
	handlers["/api/v1/auth/mfa/totp"] = h.Disable
	handlers["/api/v1/auth/mfa/recovery-codes/regenerate"] = h.RegenerateRecovery
	handlers["/api/v1/auth/mfa/totp/replacement"] = h.StartReplacement
	handlers["/api/v1/auth/mfa/totp/replacement/confirm"] = h.ConfirmReplacement
}
