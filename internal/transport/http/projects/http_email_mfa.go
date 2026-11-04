package browser

import (
	"net/http"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/management/transport/http"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/auth/project/methods"
	projectnative "github.com/Inforberi/financial-intelligence/internal/auth/project/token"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/native/transport/http"
)

func (p *binding) emailMFAHandlers(handlers map[string]http.HandlerFunc, log *zap.Logger) error {
	if p.MFASettings != nil {
		h := settingshttp.NewEmailMFA(p.EmailMFASettings, log)
		handlers["GET /api/v1/admin/auth/settings/mfa/email"], handlers["POST /api/v1/admin/auth/settings/mfa/email"] = h.Read, h.Update
	}
	if p.EmailMFA == nil {
		return nil
	}
	h, err := mfaloginhttp.NewEmailWithCookie(p.EmailMFA, projectmethods.ProjectEmailMFAPrimary{ProjectPassword: p.Password}, log, mfaloginhttp.EmailLoginCookie+"-"+string(p.Key.Binding.ProjectID))
	if err != nil {
		return err
	}
	handlers["/api/v1/auth/mfa/email/login"], handlers["/api/v1/auth/mfa/email/login/complete"] = p.requireHTTPDelivery(h.StartEmailLogin), h.CompleteEmailLogin
	management, err := mfamanagementhttp.NewEmail(p.EmailMFA, p.EmailMFA, log)
	if err != nil {
		return err
	}
	handlers["/api/v1/auth/mfa/email/preparation"], handlers["/api/v1/auth/mfa/email/preparation/confirm"] = p.requireHTTPDelivery(management.RequestEmailPreparation), management.ConfirmEmailPreparation
	handlers["GET /api/v1/auth/mfa/email"], handlers["POST /api/v1/auth/mfa/email"], handlers["DELETE /api/v1/auth/mfa/email"] = management.ReadEmailFactor, p.requireHTTPDelivery(management.EnableEmailFactor), management.DisableEmailFactor
	if p.Available("native_email_mfa") {
		native := tokennativehttp.NewNative(tokennativehttp.NativeServices{Password: projectnative.ProjectNativePasswordEmailMFAHTTP{ProjectTokens: p.Tokens}, MFA: projectnative.ProjectNativeEmailMFAHTTP{ProjectTokens: p.Tokens}}, log)
		handlers["/api/v1/auth/native/mfa/email/login"] = p.requireHTTPDelivery(native.PasswordEmailMFA)
		handlers["/api/v1/auth/native/mfa/email/complete"] = native.CompleteEmailMFA
	}
	return nil
}
