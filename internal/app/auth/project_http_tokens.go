package auth

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	tokenhttp "github.com/Inforberi/financial-intelligence/internal/auth/token/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

func (p *ProjectProfile) tokenHandlers(handlers map[string]http.HandlerFunc, log *zap.Logger) *tokenhttp.NativeHandler {
	if p.tokens == nil {
		return nil
	}
	exchange := tokenhttp.New(p.tokens, nil, log)
	handlers["/api/v1/auth/token/exchange"] = exchange.Exchange
	handlers["/.well-known/jwks.json"] = func(w http.ResponseWriter, r *http.Request) {
		public, err := p.tokens.PublicJWKS(r.Context())
		if err != nil {
			httpx.Error(w, 503, "temporarily_unavailable", "temporarily unavailable")
			return
		}
		tokenhttp.New(p.tokens, public, log).JWKS(w, r)
	}
	if p.featureReady("introspection") {
		handlers["/api/v1/internal/auth/token/introspect"] = tokenhttp.NewIntrospection(p.tokens).Inspect
	}
	if p.tokens.native == nil {
		return nil
	}
	native := tokenhttp.NewNative(tokenhttp.NativeServices{
		Password: projectNativePasswordHTTP{p.tokens}, Email: projectNativeEmailHTTP{p.tokens}, MFA: projectNativeMFAHTTP{p.tokens}, Enrollment: projectNativeMFAHTTP{p.tokens}, Tokens: p.tokens,
	}, log)
	handlers["/api/v1/auth/native/password/login"] = native.Password
	handlers["/api/v1/auth/native/email/request"] = p.requireHTTPDelivery(native.EmailRequest)
	handlers["/api/v1/auth/native/email/confirm"] = p.requireHTTPDelivery(native.EmailConfirm)
	handlers["/api/v1/auth/native/mfa/complete"] = native.CompleteMFA
	handlers["/api/v1/auth/native/mfa/enrollment"] = native.StartEnrollment
	handlers["/api/v1/auth/native/mfa/enrollment/confirm"] = native.ConfirmEnrollment
	handlers["/api/v1/auth/token/refresh"], handlers["/api/v1/auth/token/logout"] = native.Refresh, native.Logout
	return native
}

type projectNativePasswordHTTP struct{ *ProjectTokens }

func (s projectNativePasswordHTTP) Login(ctx context.Context, input tokenservice.NativePasswordInput) (*tokenservice.NativeLoginResult, error) {
	return s.LoginPassword(ctx, input)
}

type projectNativeEmailHTTP struct{ *ProjectTokens }

func (s projectNativeEmailHTTP) Request(ctx context.Context, email, ip, audience string, scope []accessdomain.PermissionKey) (*otpservice.RequestedCode, error) {
	return s.RequestEmail(ctx, email, ip, audience, scope)
}

func (s projectNativeEmailHTTP) Confirm(ctx context.Context, input otpservice.ConfirmInput) (*tokenservice.NativeLoginResult, error) {
	return s.ConfirmEmail(ctx, input)
}

type projectNativeMFAHTTP struct{ *ProjectTokens }

func (s projectNativeMFAHTTP) Complete(ctx context.Context, input mfalogin.CompleteLoginInput) (*tokenservice.RefreshResult, error) {
	return s.CompleteNativeMFA(ctx, input)
}

func (s projectNativeMFAHTTP) StartNativeRequiredEnrollment(ctx context.Context, input mfalogin.LoginEnrollmentInput) (*mfaservice.Enrollment, error) {
	return s.StartNativeEnrollment(ctx, input)
}

func (s projectNativeMFAHTTP) ConfirmNativeRequiredEnrollment(ctx context.Context, input mfalogin.ConfirmLoginEnrollmentInput) (*mfaservice.RecoveryCodes, error) {
	return s.ConfirmNativeEnrollment(ctx, input)
}
