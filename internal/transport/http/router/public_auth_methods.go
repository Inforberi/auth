package router

import (
	"github.com/go-chi/chi/v5"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
)

func publicAuthMethodsRoute(r chi.Router, h Handlers) {
	if h.PublicAuthPolicy == nil {
		return
	}
	available := settingsdomain.PublicMethods{
		Password: h.PasswordHandler != nil && h.PasswordHandler.PublicPasswordHandler != nil,
	}
	if h.Config != nil {
		available.EmailOTP = h.EmailOTP != nil && h.Config.EmailOTP.Enabled
		available.Google = h.Google != nil && h.Config.Google.Enabled
		available.Telegram = h.Telegram != nil && h.Config.Telegram.Enabled
	}
	r.Get("/methods", settingshttp.PublicMethods(h.PublicAuthPolicy, available))
}
