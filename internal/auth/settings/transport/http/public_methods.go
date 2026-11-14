package settingshttp

import (
	"context"
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type PublicMethodsResponse struct {
	Login                        MethodsResponse            `json:"login"`
	Registration                 PublicRegistrationResponse `json:"registration"`
	PasswordVerificationRequired bool                       `json:"passwordVerificationRequired"`
} // @name auth_settings_http.PublicMethodsResponse

type PublicRegistrationResponse struct {
	Password bool `json:"password"`
	Google   bool `json:"google"`
	Telegram bool `json:"telegram"`
} // @name auth_settings_http.PublicRegistrationResponse

// @Summary Read public authentication methods
// @Description Returns standalone login and registration choices for this API instance. No account data is read. Login still performs its own checks.
// @Tags Auth settings
// @Produce json
// @Success 200 {object} PublicMethodsResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/methods [get]
func PublicMethods(load func(context.Context) (domain.Policy, error), available domain.PublicMethods) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		policy, err := load(r.Context())
		if err != nil {
			httpx.Error(w, http.StatusServiceUnavailable, "temporarily_unavailable", "authentication methods are temporarily unavailable")
			return
		}
		login := MethodsResponse{
			Password: available.Password && policy.RequireMethod("password", false) == nil,
			EmailOTP: available.EmailOTP && policy.RequireMethod("emailotp", false) == nil,
			Google:   available.Google && policy.RequireMethod("google", false) == nil,
			Telegram: available.Telegram && policy.RequireMethod("telegram", false) == nil,
		}
		passwordRegistration := login.Password && policy.RequireMethod("password", true) == nil
		googleRegistration := login.Google && policy.RequireMethod("google", true) == nil
		telegramRegistration := login.Telegram && policy.RequireMethod("telegram", true) == nil
		httpx.JSON(w, http.StatusOK, PublicMethodsResponse{
			Login: login,
			Registration: PublicRegistrationResponse{
				Password: passwordRegistration,
				Google:   googleRegistration,
				Telegram: telegramRegistration,
			},
			PasswordVerificationRequired: login.Password && policy.PasswordEmailVerification == domain.VerificationRequired,
		})
	}
}
