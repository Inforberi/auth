package profile

import (
	"net/http"

	"go.uber.org/zap"

	projectmethods "github.com/Inforberi/financial-intelligence/internal/app/projects/methods"
	projectmfa "github.com/Inforberi/financial-intelligence/internal/app/projects/mfa"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/management/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/recovery/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/telegram/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/telegram/transport/http"
)

func (p *ProjectProfile) telegramMFAHandlers(handlers map[string]http.HandlerFunc, log *zap.Logger) {
	if p.mfaManagement != nil {
		h := mfamanagementhttp.NewPreferences(projectmfa.NewProjectPreferences(p.mfaManagement), log)
		handlers["GET /api/v1/auth/mfa/preference"], handlers["POST /api/v1/auth/mfa/preference"] = h.Read, h.Update
	}
	if p.mfaRecovery != nil && p.password != nil && p.mfa != nil {
		h := mfarecoveryhttp.NewRecoveryLogin(projectmethods.ProjectEmailMFAPrimary{ProjectPassword: p.password}, projectmfa.NewProjectRecoveryPrimary(p.mfa), log)
		handlers["/api/v1/auth/mfa/recovery/login"] = h.Start
	}
	if p.telegramMFA == nil {
		return
	}
	h := mfatelegramhttp.NewTelegram(p.telegramMFA, log)
	handlers["/api/v1/auth/mfa/telegram/preparation"], handlers["/api/v1/auth/mfa/telegram/preparation/confirm"] = p.requireHTTPDelivery(h.Request), h.Confirm
	handlers["GET /api/v1/auth/mfa/telegram"], handlers["POST /api/v1/auth/mfa/telegram"], handlers["DELETE /api/v1/auth/mfa/telegram"] = h.Read, p.requireHTTPDelivery(h.Enable), h.Disable
	handlers["/api/v1/auth/mfa/telegram/webhook"] = p.telegramMFA.WebhookHTTP
	settings := settingstelegramhttp.NewTelegram(p.telegramMFA, log)
	handlers["GET /api/v1/admin/auth/settings/mfa/telegram/bot"], handlers["POST /api/v1/admin/auth/settings/mfa/telegram/bot"] = settings.ReadBot, settings.UpdateBot
	handlers["GET /api/v1/admin/auth/settings/mfa/telegram"], handlers["POST /api/v1/admin/auth/settings/mfa/telegram"] = settings.ReadPolicy, settings.UpdatePolicy
	handlers["/api/v1/admin/auth/settings/mfa/telegram/webhook"] = settings.ActivateWebhook
}
