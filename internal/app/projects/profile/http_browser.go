package profile

import (
	"net/http"

	"go.uber.org/zap"

	projectaccount "github.com/Inforberi/financial-intelligence/internal/app/projects/account"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/app/projects/methods"
	projectmfa "github.com/Inforberi/financial-intelligence/internal/app/projects/mfa"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/email/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
	otphttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/transport/http"
	googlehttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/google/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/provisioning/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/recovery/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
	telegramhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/transport/http"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/providers/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/retention/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/smtp/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

func (p *ProjectProfile) browserHandlers(log *zap.Logger) map[string]http.HandlerFunc {
	handlers := make(map[string]http.HandlerFunc)
	if p.password != nil {
		h := passwordhttp.NewPublic(p.password, log).WithEmailMFACookie(mfaloginhttp.EmailLoginCookie + "-" + string(p.key.Binding.ProjectID))
		handlers["/api/v1/auth/login/email"], handlers["/api/v1/auth/register/email"] = h.LoginByEmail, h.Register
		handlers["/api/v1/auth/change-password"] = p.password.ChangePasswordHandler(log)
		handlers["/api/v1/auth/reauthenticate/password"] = passwordhttp.NewReauthentication(projectmethods.ProjectPasswordReauthenticationHTTP{ProjectPassword: p.password}, log).Confirm
		if p.featureReady("verification") && p.policy.Policy.PasswordEmailVerification != settingsdomain.VerificationDisabled {
			handlers["/api/v1/auth/register/email"] = p.requireHTTPDelivery(h.Register)
		}
		if p.featureReady("temporary_password") {
			temporary := passwordprovisioninghttp.NewTemporaryPassword(projectmethods.ProjectTemporaryHTTP{ProjectPassword: p.password}, log)
			handlers["/api/v1/auth/temporary-password/login"], handlers["/api/v1/auth/temporary-password/complete"] = temporary.Login, temporary.Complete
		}
	}
	if p.verification != nil {
		h := accountemailhttp.NewVerification(projectaccount.ProjectVerificationHTTP{ProjectEmail: p.verification}, log)
		handlers["/api/v1/auth/email/resend"], handlers["/api/v1/auth/email/verify"] = p.requireHTTPDelivery(h.Resend), p.requireHTTPDelivery(h.Confirm)
	}
	if p.recovery != nil {
		h := passwordrecoveryhttp.NewRecovery(projectaccount.ProjectRecoveryHTTP{ProjectEmail: p.recovery}, log)
		handlers["/api/v1/auth/forgot-password"], handlers["/api/v1/auth/reset-password"] = p.requireHTTPDelivery(h.Forgot), p.requireHTTPDelivery(h.Reset)
	}
	if p.emailOTP != nil {
		h := otphttp.New(p.emailOTP, log)
		handlers["/api/v1/auth/email-otp/request"], handlers["/api/v1/auth/email-otp/confirm"] = p.requireHTTPDelivery(h.Request), p.requireHTTPDelivery(h.Confirm)
		handlers["/api/v1/auth/reauthenticate/email/request"], handlers["/api/v1/auth/reauthenticate/email/confirm"] = p.requireHTTPDelivery(h.RequestReauthentication), p.requireHTTPDelivery(h.ConfirmReauthentication)
	}
	if p.google != nil {
		h := googlehttp.New(p.google, log)
		handlers["/api/v1/auth/google/start"], handlers["/api/v1/auth/google/callback"] = h.Start, h.Callback
		handlers["POST /api/v1/auth/google/link"], handlers["DELETE /api/v1/auth/google/link"] = h.StartLink, p.requirePasswordFallback(h.Unlink)
	}
	if p.telegram != nil {
		h := telegramhttp.New(p.telegram, log)
		handlers["/api/v1/auth/telegram/start"], handlers["/api/v1/auth/telegram/callback"] = h.Start, h.Callback
		handlers["POST /api/v1/auth/telegram/link"], handlers["DELETE /api/v1/auth/telegram/link"] = h.StartLink, p.requirePasswordFallback(h.Unlink)
	}
	if p.mfa != nil {
		h := mfaloginhttp.New(projectmfa.ProjectBrowserMFAHTTP{ProjectMFA: p.mfa}, log)
		handlers["/api/v1/auth/mfa/login/complete"] = h.CompleteLogin
		handlers["/api/v1/auth/mfa/login/enrollment"], handlers["/api/v1/auth/mfa/login/enrollment/confirm"] = h.StartLoginEnrollment, h.ConfirmLoginEnrollment
	}
	if p.userDirectory != nil {
		directory := accounthttp.NewUserDirectory(p.userDirectory, log)
		handlers["GET /api/v1/admin/users"], handlers["GET /api/v1/admin/users/{id}"] = directory.List, directory.Read
	}
	if p.userLifecycle != nil {
		lifecycle := accounthttp.NewUserLifecycle(p.userLifecycle, log)
		handlers["POST /api/v1/admin/users/{id}/status"], handlers["DELETE /api/v1/admin/users/{id}"] = lifecycle.ChangeStatus, lifecycle.Delete
	}
	if p.authSettings != nil {
		settings := settingshttp.New(p.authSettings, settingsdomain.PublicMethods{}, log)
		handlers["GET /api/v1/admin/auth/settings"], handlers["POST /api/v1/admin/auth/settings"] = settings.Read, settings.Update
	}
	if p.smtpSettings != nil {
		smtp := settingssmtphttp.NewSMTP(p.smtpSettings, log)
		handlers["GET /api/v1/admin/auth/settings/smtp"], handlers["POST /api/v1/admin/auth/settings/smtp"] = smtp.Read, smtp.Update
		handlers["POST /api/v1/admin/auth/settings/smtp/test"] = smtp.TestConnection
	}
	if p.providerSettings != nil {
		providers := settingsprovidershttp.NewProviders(p.providerSettings, log)
		handlers["GET /api/v1/admin/auth/settings/providers/{provider}"], handlers["POST /api/v1/admin/auth/settings/providers/{provider}"] = providers.Read, providers.Update
	}
	if p.retentionSettings != nil {
		retention := settingsretentionhttp.NewRetention(p.retentionSettings, log)
		handlers["GET /api/v1/admin/auth/settings/retention"], handlers["POST /api/v1/admin/auth/settings/retention"] = retention.Read, retention.Update
	}
	if p.mfaSettings != nil {
		mfa := settingshttp.NewMFA(p.mfaSettings, log)
		handlers["GET /api/v1/admin/auth/settings/mfa"] = mfa.Read
		handlers["POST /api/v1/admin/auth/settings/mfa"] = mfa.Update
	}
	p.accessHandlers(handlers, log)
	p.provisioningHandlers(handlers, log)
	p.emailManagementHandlers(handlers, log)
	p.mfaManagementHandlers(handlers, log)
	return handlers
}

func (p *ProjectProfile) requireHTTPDelivery(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !p.deliveryReady() {
			httpx.Error(w, 503, "temporarily_unavailable", "temporarily unavailable")
			return
		}
		next(w, r)
	}
}

func (p *ProjectProfile) requirePasswordFallback(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !p.featureReady("password") {
			httpx.Error(w, 409, "last_login_method", "cannot remove last login method")
			return
		}
		next(w, r)
	}
}
