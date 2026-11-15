package router

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"
)

// NewOperator keeps platform routes separate from ordinary project administration.
func NewOperator(h Handlers) (http.Handler, error) {
	if h.Config == nil || !h.Config.Platform.Enabled || h.PasswordHandler == nil || h.MFA == nil || h.Middleware == nil || h.Session == nil || h.Recovery == nil || h.ReadyCheck == nil {
		return nil, errors.New("incomplete operator HTTP profile")
	}
	if err := h.Config.ValidatePlatform(); err != nil {
		return nil, err
	}
	if err := validateProjectHTTP(h); err != nil {
		return nil, err
	}
	origin, err := url.Parse(h.Config.Platform.Origin)
	if err != nil {
		return nil, err
	}
	r := baseRouter(h)
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			// No forwarded-host fallback or plaintext listener for the initial platform profile.
			if r.Host != origin.Host || r.TLS == nil {
				http.NotFound(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	r.Get("/health/live", live)
	r.Get("/health/ready", readiness(h.ReadyCheck))
	r.Route("/api/v1", func(r chi.Router) {
		setupRoutes(r, h)
		administrativeLoginRoutes(r, h)
		operatorMFASettingsRoutes(r, h)
		platformProjectRoutes(r, h)
		if h.Operators != nil {
			operators := r.With(browserProtection(h), h.Middleware.NoRefreshAuth)
			operators.Get("/platform/operators", h.Operators.List)
			operators.Post("/platform/operators", h.Operators.Apply)
		}
		r.Route("/auth", func(r chi.Router) {
			r.Use(browserProtection(h))
			r.Post("/forgot-password", h.Recovery.Forgot)
			r.Post("/reset-password", h.Recovery.Reset)
			if h.Activation != nil {
				r.Post("/invitations/activate", h.Activation.Activate)
			}
			r.Post("/mfa/login/complete", h.MFALogin.CompleteLogin)
			r.Post("/mfa/login/enrollment", h.MFALogin.StartLoginEnrollment)
			r.Post("/mfa/login/enrollment/confirm", h.MFALogin.ConfirmLoginEnrollment)
			if h.Config.MFA.RecoveryEnabled {
				r.Post("/mfa/recovery/start", h.MFARecovery.StartRecovery)
				r.Post("/mfa/recovery/complete", h.MFARecovery.CompleteRecovery)
			}
			sessionRoutes(r, h)
			owner := r.With(h.Middleware.NoRefreshAuth)
			owner.Post("/change-password", h.PasswordHandler.ChangePassword)
			owner.Get("/mfa/status", h.MFA.ReadStatus)
			owner.Post("/mfa/totp/enrollment", h.MFA.StartEnrollment)
			owner.Post("/mfa/totp/enrollment/confirm", h.MFA.ConfirmEnrollment)
			owner.Post("/mfa/step-up", h.MFA.StepUp)
			owner.Delete("/mfa/totp", h.MFA.Disable)
			owner.Post("/mfa/recovery-codes/regenerate", h.MFA.RegenerateRecovery)
			owner.Post("/mfa/totp/replacement", h.MFA.StartReplacement)
			owner.Post("/mfa/totp/replacement/confirm", h.MFA.ConfirmReplacement)
		})
	})
	return r, nil
}

func validateProjectHTTP(h Handlers) error {
	if h.Projects != nil && h.ProjectCapacity == nil {
		return errors.New("project HTTP routes require capacity admission")
	}
	if (h.ProjectRoles != nil || h.ProjectUsers != nil || h.ProjectAuthPolicy != nil) && (h.Projects == nil || !h.Config.Platform.Runtime.Enabled) {
		return errors.New("project runtime routes require enabled runtime and the guarded catalog group")
	}
	return nil
}

func platformProjectRoutes(r chi.Router, h Handlers) {
	if h.Projects == nil {
		return
	}
	r.Route("/platform", func(r chi.Router) {
		r.Use(browserProtection(h), h.Middleware.NoRefreshAuth)
		r = r.With(h.ProjectCapacity)
		r.Get("/projects", h.Projects.List)
		r.Post("/projects", h.Projects.Create)
		r.Get("/projects/{id}", h.Projects.Read)
		r.Post("/projects/{id}/name", h.Projects.Rename)
		r.Post("/projects/{id}/preparation", h.Projects.RequestPreparation)
		r.Get("/projects/{id}/preparation/{operationId}", h.Projects.ReadPreparation)
		r.Get("/projects/{id}/deletion-preview", h.Projects.PreviewDeletion)
		r.Post("/projects/{id}/deletion", h.Projects.ConfirmDeletion)
		r.Get("/projects/{id}/deletion/{operationId}", h.Projects.ReadDeletion)
		r.Post("/projects/{id}/suspend", h.Projects.Suspend)
		r.Post("/projects/{id}/resume", h.Projects.Resume)
		r.Post("/projects/{id}/retry", h.Projects.Retry)
		if h.ProjectAuthPolicy != nil {
			r.Get("/projects/{id}/auth/settings", h.ProjectAuthPolicy.Read)
			r.Post("/projects/{id}/auth/settings", h.ProjectAuthPolicy.Update)
			r.Get("/projects/{id}/auth/settings/mfa", h.ProjectAuthPolicy.ReadMFA)
			r.Post("/projects/{id}/auth/settings/mfa", h.ProjectAuthPolicy.UpdateMFA)
			r.Get("/projects/{id}/auth/settings/sessions", h.ProjectAuthPolicy.ReadSessions)
			r.Post("/projects/{id}/auth/settings/sessions", h.ProjectAuthPolicy.UpdateSessions)
			r.Get("/projects/{id}/auth/settings/link-lifetimes", h.ProjectAuthPolicy.ReadLinkLifetimes)
			r.Post("/projects/{id}/auth/settings/link-lifetimes", h.ProjectAuthPolicy.UpdateLinkLifetimes)
			r.Get("/projects/{id}/auth/settings/credential-lifetimes", h.ProjectAuthPolicy.ReadCredentialLifetimes)
			r.Post("/projects/{id}/auth/settings/credential-lifetimes", h.ProjectAuthPolicy.UpdateCredentialLifetimes)
			r.Get("/projects/{id}/auth/settings/login-budgets", h.ProjectAuthPolicy.ReadLoginBudgets)
			r.Post("/projects/{id}/auth/settings/login-budgets", h.ProjectAuthPolicy.UpdateLoginBudgets)
			r.Get("/projects/{id}/auth/settings/operation-budgets", h.ProjectAuthPolicy.ReadOperationBudgets)
			r.Post("/projects/{id}/auth/settings/operation-budgets", h.ProjectAuthPolicy.UpdateOperationBudgets)
			r.Get("/projects/{id}/auth/settings/frontend", h.ProjectAuthPolicy.ReadFrontends)
			r.Post("/projects/{id}/auth/settings/frontend", h.ProjectAuthPolicy.UpdateFrontends)
			r.Get("/projects/{id}/auth/settings/retention", h.ProjectAuthPolicy.ReadRetention)
			r.Post("/projects/{id}/auth/settings/retention", h.ProjectAuthPolicy.UpdateRetention)
			r.Get("/projects/{id}/auth/settings/smtp", h.ProjectAuthPolicy.ReadSMTP)
			r.Post("/projects/{id}/auth/settings/smtp", h.ProjectAuthPolicy.UpdateSMTP)
			r.Get("/projects/{id}/auth/settings/providers/{provider}", h.ProjectAuthPolicy.ReadProvider)
			r.Post("/projects/{id}/auth/settings/providers/{provider}", h.ProjectAuthPolicy.UpdateProvider)
			r.Get("/projects/{id}/auth/settings/telegram-bot", h.ProjectAuthPolicy.ReadTelegramBot)
			r.Post("/projects/{id}/auth/settings/telegram-bot", h.ProjectAuthPolicy.UpdateTelegramBot)
			r.Post("/projects/{id}/auth/settings/telegram-bot/webhook", h.ProjectAuthPolicy.ActivateTelegramWebhook)
			r.Get("/projects/{id}/auth/settings/operations/{operationId}", h.ProjectAuthPolicy.ReadOutcome)
		}
		if h.ProjectUsers != nil {
			r.Get("/projects/{id}/users", h.ProjectUsers.List)
			r.Post("/projects/{id}/users", h.ProjectUsers.Create)
			r.Get("/projects/{id}/users/{userId}", h.ProjectUsers.Read)
			r.Post("/projects/{id}/users/{userId}/lifecycle", h.ProjectUsers.ChangeLifecycle)
		}
		if h.ProjectRoles != nil {
			r.Get("/projects/{id}/roles", h.ProjectRoles.ListRoles)
			r.Get("/projects/{id}/roles/{roleId}", h.ProjectRoles.ReadRole)
			r.Put("/projects/{id}/roles/{roleId}", h.ProjectRoles.Edit)
			r.Post("/projects/{id}/users/{userId}/administrator", h.ProjectRoles.ChangeAdministrator)
			r.Post("/projects/{id}/roles", h.ProjectRoles.Create)
			r.Post("/projects/{id}/users/{userId}/roles/{roleId}/grant", h.ProjectRoles.Grant)
			r.Post("/projects/{id}/users/{userId}/roles/{roleId}/revoke", h.ProjectRoles.Revoke)
			r.Get("/projects/{id}/role-operations/{operationId}", h.ProjectRoles.Read)
			r.Post("/projects/{id}/role-operations/{operationId}/reconcile", h.ProjectRoles.Reconcile)
		}
	})
}
