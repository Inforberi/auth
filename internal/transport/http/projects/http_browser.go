package browser

import (
	"net/http"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/email/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
	otphttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/transport/http"
	googlehttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/google/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/provisioning/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/recovery/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
	telegramhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/transport/http"
	projectaccount "github.com/Inforberi/financial-intelligence/internal/auth/project/account"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/auth/project/methods"
	projectmfa "github.com/Inforberi/financial-intelligence/internal/auth/project/mfa"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/providers/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/retention/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/smtp/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

func (p *binding) browserHandlers(log *zap.Logger) map[string]http.HandlerFunc {
	handlers := make(map[string]http.HandlerFunc)
	if p.Password != nil {
		h := passwordhttp.NewPublic(p.Password, log).WithEmailMFACookie(mfaloginhttp.EmailLoginCookie + "-" + string(p.Key.Binding.ProjectID))
		handlers["/api/v1/auth/login/email"], handlers["/api/v1/auth/register/email"] = h.LoginByEmail, h.Register
		handlers["/api/v1/auth/change-password"] = passwordhttp.NewChangePassword(p.Password, p.Password, log).ChangePassword
		handlers["/api/v1/auth/reauthenticate/password"] = passwordhttp.NewReauthentication(projectmethods.ProjectPasswordReauthenticationHTTP{ProjectPassword: p.Password}, log).Confirm
		if p.Available("verification") && p.EmailVerificationPolicy != settingsdomain.VerificationDisabled {
			handlers["/api/v1/auth/register/email"] = p.requireHTTPDelivery(h.Register)
		}
		if p.Available("temporary_password") {
			temporary := passwordprovisioninghttp.NewTemporaryPassword(projectmethods.ProjectTemporaryHTTP{ProjectPassword: p.Password}, log)
			handlers["/api/v1/auth/temporary-password/login"], handlers["/api/v1/auth/temporary-password/complete"] = temporary.Login, temporary.Complete
		}
	}
	if p.Verification != nil {
		h := accountemailhttp.NewVerification(projectaccount.ProjectVerificationHTTP{ProjectEmail: p.Verification}, log)
		handlers["/api/v1/auth/email/resend"], handlers["/api/v1/auth/email/verify"] = p.requireHTTPDelivery(h.Resend), p.requireHTTPDelivery(h.Confirm)
	}
	if p.Recovery != nil {
		h := passwordrecoveryhttp.NewRecovery(projectaccount.ProjectRecoveryHTTP{ProjectEmail: p.Recovery}, log)
		handlers["/api/v1/auth/forgot-password"], handlers["/api/v1/auth/reset-password"] = p.requireHTTPDelivery(h.Forgot), p.requireHTTPDelivery(h.Reset)
	}
	if p.EmailOTP != nil {
		h := otphttp.New(p.EmailOTP, log)
		handlers["/api/v1/auth/email-otp/request"], handlers["/api/v1/auth/email-otp/confirm"] = p.requireHTTPDelivery(h.Request), p.requireHTTPDelivery(h.Confirm)
		handlers["/api/v1/auth/reauthenticate/email/request"], handlers["/api/v1/auth/reauthenticate/email/confirm"] = p.requireHTTPDelivery(h.RequestReauthentication), p.requireHTTPDelivery(h.ConfirmReauthentication)
	}
	if p.Google != nil {
		h := googlehttp.New(p.Google, log)
		handlers["/api/v1/auth/google/start"], handlers["/api/v1/auth/google/callback"] = h.Start, h.Callback
		handlers["POST /api/v1/auth/google/link"], handlers["DELETE /api/v1/auth/google/link"] = h.StartLink, p.requirePasswordFallback(h.Unlink)
	}
	if p.Telegram != nil {
		h := telegramhttp.New(p.Telegram, log)
		handlers["/api/v1/auth/telegram/start"], handlers["/api/v1/auth/telegram/callback"] = h.Start, h.Callback
		handlers["POST /api/v1/auth/telegram/link"], handlers["DELETE /api/v1/auth/telegram/link"] = h.StartLink, p.requirePasswordFallback(h.Unlink)
	}
	if p.MFA != nil {
		h := mfaloginhttp.New(projectmfa.ProjectBrowserMFAHTTP{ProjectMFA: p.MFA}, log)
		handlers["/api/v1/auth/mfa/login/complete"] = h.CompleteLogin
		handlers["/api/v1/auth/mfa/login/enrollment"], handlers["/api/v1/auth/mfa/login/enrollment/confirm"] = h.StartLoginEnrollment, h.ConfirmLoginEnrollment
	}
	if p.UserDirectory != nil {
		directory := accounthttp.NewUserDirectory(p.UserDirectory, log)
		handlers["GET /api/v1/admin/users"], handlers["GET /api/v1/admin/users/{id}"] = directory.List, directory.Read
	}
	if p.UserLifecycle != nil {
		lifecycle := accounthttp.NewUserLifecycle(p.UserLifecycle, log)
		handlers["POST /api/v1/admin/users/{id}/status"], handlers["DELETE /api/v1/admin/users/{id}"] = lifecycle.ChangeStatus, lifecycle.Delete
	}
	if p.AuthSettings != nil {
		settings := settingshttp.New(p.AuthSettings, settingsdomain.PublicMethods{}, log)
		handlers["GET /api/v1/admin/auth/settings"], handlers["POST /api/v1/admin/auth/settings"] = settings.Read, settings.Update
	}
	if p.SMTPSettings != nil {
		smtp := settingssmtphttp.NewSMTP(p.SMTPSettings, log)
		handlers["GET /api/v1/admin/auth/settings/smtp"], handlers["POST /api/v1/admin/auth/settings/smtp"] = smtp.Read, smtp.Update
		handlers["POST /api/v1/admin/auth/settings/smtp/test"] = smtp.TestConnection
	}
	if p.ProviderSettings != nil {
		providers := settingsprovidershttp.NewProviders(p.ProviderSettings, log)
		handlers["GET /api/v1/admin/auth/settings/providers/{provider}"], handlers["POST /api/v1/admin/auth/settings/providers/{provider}"] = providers.Read, providers.Update
	}
	if p.RetentionSettings != nil {
		retention := settingsretentionhttp.NewRetention(p.RetentionSettings, log)
		handlers["GET /api/v1/admin/auth/settings/retention"], handlers["POST /api/v1/admin/auth/settings/retention"] = retention.Read, retention.Update
	}
	if p.MFASettings != nil {
		mfa := settingshttp.NewMFA(p.MFASettings, log)
		handlers["GET /api/v1/admin/auth/settings/mfa"] = mfa.Read
		handlers["POST /api/v1/admin/auth/settings/mfa"] = mfa.Update
	}
	p.accessHandlers(handlers, log)
	p.provisioningHandlers(handlers, log)
	p.emailManagementHandlers(handlers, log)
	p.mfaManagementHandlers(handlers, log)
	return handlers
}

func (p *binding) requireHTTPDelivery(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !p.DeliveryReady() {
			httpx.Error(w, 503, "temporarily_unavailable", "temporarily unavailable")
			return
		}
		next(w, r)
	}
}

func (p *binding) requirePasswordFallback(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !p.Available("password") {
			httpx.Error(w, 409, "last_login_method", "cannot remove last login method")
			return
		}
		next(w, r)
	}
}
