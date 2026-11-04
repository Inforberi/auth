package profile

import (
	"context"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	projectmethods "github.com/Inforberi/financial-intelligence/internal/app/projects/methods"
	projectnative "github.com/Inforberi/financial-intelligence/internal/app/projects/native"
	projectsettings "github.com/Inforberi/financial-intelligence/internal/app/projects/settings"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/management/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/native/transport/http"
)

func (p *ProjectProfile) emailMFAHandlers(handlers map[string]http.HandlerFunc, log *zap.Logger) error {
	if p.mfaSettings != nil {
		h := settingshttp.NewEmailMFA(projectsettings.NewProjectEmailMFASettings(p.runtimeBinding(), func() bool { return p.emailMFA != nil && p.deliveryReady() }, func(ctx context.Context, pool *pgxpool.Pool) error { return p.emailMFA.CheckSMTP(ctx, pool) }), log)
		handlers["GET /api/v1/admin/auth/settings/mfa/email"], handlers["POST /api/v1/admin/auth/settings/mfa/email"] = h.Read, h.Update
	}
	if p.emailMFA == nil {
		return nil
	}
	h, err := mfaloginhttp.NewEmailWithCookie(p.emailMFA, projectmethods.ProjectEmailMFAPrimary{ProjectPassword: p.password}, log, mfaloginhttp.EmailLoginCookie+"-"+string(p.key.Binding.ProjectID))
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
		native := tokennativehttp.NewNative(tokennativehttp.NativeServices{Password: projectnative.ProjectNativePasswordEmailMFAHTTP{ProjectTokens: p.tokens}, MFA: projectnative.ProjectNativeEmailMFAHTTP{ProjectTokens: p.tokens}}, log)
		handlers["/api/v1/auth/native/mfa/email/login"] = p.requireHTTPDelivery(native.PasswordEmailMFA)
		handlers["/api/v1/auth/native/mfa/email/complete"] = native.CompleteEmailMFA
	}
	return nil
}
