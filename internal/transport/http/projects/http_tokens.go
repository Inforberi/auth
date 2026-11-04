package browser

import (
	"net/http"

	"go.uber.org/zap"

	projectnative "github.com/Inforberi/financial-intelligence/internal/auth/project/token"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/introspection/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/native/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

func (p *binding) tokenHandlers(handlers map[string]http.HandlerFunc, log *zap.Logger) *tokennativehttp.NativeHandler {
	if p.Tokens == nil {
		return nil
	}
	exchange := tokenhttp.New(p.Tokens, nil, log)
	handlers["/api/v1/auth/token/exchange"] = exchange.Exchange
	handlers["/.well-known/jwks.json"] = func(w http.ResponseWriter, r *http.Request) {
		public, err := p.Tokens.PublicJWKS(r.Context())
		if err != nil {
			httpx.Error(w, 503, "temporarily_unavailable", "temporarily unavailable")
			return
		}
		tokenhttp.New(p.Tokens, public, log).JWKS(w, r)
	}
	if p.Available("introspection") {
		handlers["/api/v1/internal/auth/token/introspect"] = tokenintrospectionhttp.NewIntrospection(p.Tokens).Inspect
	}
	if !p.Tokens.NativeAvailable() {
		return nil
	}
	native := tokennativehttp.NewNative(tokennativehttp.NativeServices{
		Password: projectnative.ProjectNativePasswordHTTP{ProjectTokens: p.Tokens}, Email: projectnative.ProjectNativeEmailHTTP{ProjectTokens: p.Tokens}, MFA: projectnative.ProjectNativeMFAHTTP{ProjectTokens: p.Tokens}, Enrollment: projectnative.ProjectNativeMFAHTTP{ProjectTokens: p.Tokens}, Tokens: p.Tokens,
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
