package auth

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
	otphttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/transport/http"
	googlehttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/google/transport/http"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	passwordhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
	telegramhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/transport/http"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

func (p *ProjectProfile) browserHandlers(log *zap.Logger) map[string]http.HandlerFunc {
	handlers := make(map[string]http.HandlerFunc)
	if p.password != nil {
		h := passwordhttp.NewPublic(p.password, log)
		handlers["/api/v1/auth/login/email"], handlers["/api/v1/auth/register/email"] = h.LoginByEmail, h.Register
		handlers["/api/v1/auth/change-password"] = passwordhttp.NewChangePassword(p.password, p.password.limits, log).ChangePassword
		handlers["/api/v1/auth/reauthenticate/password"] = passwordhttp.NewReauthentication(projectPasswordReauthenticationHTTP{p.password}, log).Confirm
		if p.featureReady("verification") && p.policy.Policy.PasswordEmailVerification != settingsdomain.VerificationDisabled {
			handlers["/api/v1/auth/register/email"] = p.requireHTTPDelivery(h.Register)
		}
		if p.featureReady("temporary_password") {
			temporary := passwordhttp.NewTemporaryPassword(projectTemporaryHTTP{p.password}, log)
			handlers["/api/v1/auth/temporary-password/login"], handlers["/api/v1/auth/temporary-password/complete"] = temporary.Login, temporary.Complete
		}
	}
	if p.verification != nil {
		h := accounthttp.NewVerification(projectVerificationHTTP{p.verification}, log)
		handlers["/api/v1/auth/email/resend"], handlers["/api/v1/auth/email/verify"] = p.requireHTTPDelivery(h.Resend), p.requireHTTPDelivery(h.Confirm)
	}
	if p.recovery != nil {
		h := passwordhttp.NewRecovery(projectRecoveryHTTP{p.recovery}, log)
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
		h := mfahttp.New(nil, projectBrowserMFAHTTP{p.mfa}, log)
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

type projectVerificationHTTP struct{ *ProjectEmail }

type projectPasswordReauthenticationHTTP struct{ *ProjectPassword }

func (s projectPasswordReauthenticationHTTP) Confirm(ctx context.Context, user accountdomain.UserID, hash, password, ip string) (*passwordservice.ReauthenticationResult, error) {
	return s.ConfirmReauthentication(ctx, user, hash, password, ip)
}

func (s projectVerificationHTTP) Resend(ctx context.Context, email, ip string) error {
	return s.ResendVerification(ctx, email, ip)
}

func (s projectVerificationHTTP) Confirm(ctx context.Context, token, ip string) error {
	return s.ConfirmVerification(ctx, token, ip)
}

type projectRecoveryHTTP struct{ *ProjectEmail }

func (s projectRecoveryHTTP) Forgot(ctx context.Context, email, ip string) error {
	return s.ForgotPassword(ctx, email, ip)
}

func (s projectRecoveryHTTP) Reset(ctx context.Context, token, password, confirmation, ip string) error {
	return s.ResetPassword(ctx, token, password, confirmation, ip)
}

type projectBrowserMFAHTTP struct{ *projectMFA }

func (s projectBrowserMFAHTTP) Complete(ctx context.Context, input mfaservice.CompleteLoginInput) (*mfaservice.LoginSession, error) {
	return s.CompleteMFA(ctx, input)
}

func (s projectBrowserMFAHTTP) StartRequiredEnrollment(ctx context.Context, input mfaservice.LoginEnrollmentInput) (*mfaservice.Enrollment, error) {
	return s.StartMFAEnrollment(ctx, input)
}

func (s projectBrowserMFAHTTP) ConfirmRequiredEnrollment(ctx context.Context, input mfaservice.ConfirmLoginEnrollmentInput) (*mfaservice.RecoveryCodes, error) {
	return s.ConfirmMFAEnrollment(ctx, input)
}

type projectTemporaryHTTP struct{ *ProjectPassword }

func (s projectTemporaryHTTP) Login(ctx context.Context, email, password, ip string) (*passwordservice.TemporaryLoginResult, error) {
	return s.BeginTemporaryPassword(ctx, email, password, ip)
}

func (s projectTemporaryHTTP) Complete(ctx context.Context, token, password, confirmation, ip string) error {
	return s.CompleteTemporaryPassword(ctx, token, password, confirmation, ip)
}
