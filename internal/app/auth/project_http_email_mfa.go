package auth

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	mfaloginhttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/transport/http"
	mfamanagementhttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/management/transport/http"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	tokenhttp "github.com/Inforberi/financial-intelligence/internal/auth/token/transport/http"
)

func (p *ProjectProfile) emailMFAHandlers(handlers map[string]http.HandlerFunc, log *zap.Logger) error {
	if p.mfaSettings != nil {
		h := settingshttp.NewEmailMFA(projectEmailMFASettings{profile: p}, log)
		handlers["GET /api/v1/admin/auth/settings/mfa/email"], handlers["POST /api/v1/admin/auth/settings/mfa/email"] = h.Read, h.Update
	}
	if p.emailMFA == nil {
		return nil
	}
	h, err := mfaloginhttp.NewEmailWithCookie(p.emailMFA, projectEmailMFAPrimary{p}, log, mfaloginhttp.EmailLoginCookie+"-"+string(p.key.Binding.ProjectID))
	if err != nil {
		return err
	}
	handlers["/api/v1/auth/mfa/email/login"], handlers["/api/v1/auth/mfa/email/login/complete"] = p.requireHTTPDelivery(h.StartEmailLogin), h.CompleteEmailLogin
	management, err := mfamanagementhttp.NewEmail(p.emailMFA, p.emailMFA, log)
	if err != nil {
		return err
	}
	handlers["/api/v1/auth/mfa/email/preparation"], handlers["/api/v1/auth/mfa/email/preparation/confirm"] = p.requireHTTPDelivery(management.RequestEmailPreparation), management.ConfirmEmailPreparation
	handlers["GET /api/v1/auth/mfa/email"], handlers["POST /api/v1/auth/mfa/email"], handlers["DELETE /api/v1/auth/mfa/email"] = management.ReadEmailFactor, p.requireHTTPDelivery(management.EnableEmailFactor), management.DisableEmailFactor
	if p.featureReady("native_email_mfa") {
		native := tokenhttp.NewNative(tokenhttp.NativeServices{Password: projectNativePasswordEmailMFAHTTP{p.tokens}, MFA: projectNativeEmailMFAHTTP{p.tokens}}, log)
		handlers["/api/v1/auth/native/mfa/email/login"] = p.requireHTTPDelivery(native.PasswordEmailMFA)
		handlers["/api/v1/auth/native/mfa/email/complete"] = native.CompleteEmailMFA
	}
	return nil
}

type projectEmailMFAPrimary struct{ profile *ProjectProfile }

func (s projectEmailMFAPrimary) Authenticate(ctx context.Context, input passwordservice.LoginInput) (mfaservice.PrimaryProof, error) {
	if s.profile.password == nil {
		return mfaservice.PrimaryProof{}, mfadomain.ErrUnavailable
	}
	return s.profile.password.Authenticate(ctx, input)
}

type projectNativePasswordEmailMFAHTTP struct{ *ProjectTokens }

func (s projectNativePasswordEmailMFAHTTP) Login(ctx context.Context, input tokenservice.NativePasswordInput) (*tokenservice.NativeLoginResult, error) {
	return s.LoginPasswordEmailMFA(ctx, input)
}

type projectNativeEmailMFAHTTP struct{ *ProjectTokens }

func (s projectNativeEmailMFAHTTP) Complete(ctx context.Context, input mfalogin.CompleteLoginInput) (*tokenservice.RefreshResult, error) {
	return s.CompleteNativeEmailMFA(ctx, input)
}
