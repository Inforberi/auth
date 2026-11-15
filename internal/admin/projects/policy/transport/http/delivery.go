package http

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"

	operators "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	catalog "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	settings "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	providers "github.com/Inforberi/financial-intelligence/internal/auth/settings/providers/service"
	smtp "github.com/Inforberi/financial-intelligence/internal/auth/settings/smtp/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type ProjectDelivery interface {
	ReadProjectSMTP(context.Context, operators.Principal, domain.DirectoryTarget) (settings.SMTPSnapshot, error)
	UpdateProjectSMTP(context.Context, operators.Principal, domain.DirectoryTarget, smtp.SMTPUpdateInput) (settings.SMTPSnapshot, error)
	ReadProjectProvider(context.Context, operators.Principal, domain.DirectoryTarget, string) (settings.ProviderSnapshot, error)
	UpdateProjectProvider(context.Context, operators.Principal, domain.DirectoryTarget, providers.ProviderUpdateInput) (settings.ProviderSnapshot, error)
}

func (h *AuthPolicyHandler) WithProjectDelivery(backend ProjectDelivery) *AuthPolicyHandler {
	h.delivery = backend
	return h
}

type ProjectSMTPRequest struct {
	ExpectedVersion int64                `json:"expectedVersion"`
	Config          *settings.SMTPConfig `json:"configuration"`
	Password        *string              `json:"password,omitempty"`
} // @name project_http.ProjectSMTPRequest

type ProjectProviderRequest struct {
	ExpectedVersion int64   `json:"expectedVersion"`
	ClientID        string  `json:"clientId"`
	Secret          *string `json:"secret,omitempty"`
} // @name project_http.ProjectProviderRequest

// @Summary Read project SMTP settings
// @Tags Platform Projects
// @Success 200 {object} settings.SMTPSnapshot
// @Param id path string true "Project UUID"
// @Param expectedVersion query int true "Current project version"
// @Param expectedGeneration query int true "Current project generation"
// @Security SessionCookie
// @ID getPlatformProjectsByIdAuthSettingsSmtp
// @Router /api/v1/platform/projects/{id}/auth/settings/smtp [get]
func (h *AuthPolicyHandler) ReadSMTP(w http.ResponseWriter, r *http.Request) {
	h.projectSMTP(w, r, false)
}

// @Summary Update project SMTP settings
// @Tags Platform Projects
// @Param body body ProjectSMTPRequest true "Configuration and optional replacement password"
// @Success 200 {object} settings.SMTPSnapshot
// @Param id path string true "Project UUID"
// @Param expectedVersion query int true "Current project version"
// @Param expectedGeneration query int true "Current project generation"
// @Security SessionCookie
// @ID postPlatformProjectsByIdAuthSettingsSmtp
// @Router /api/v1/platform/projects/{id}/auth/settings/smtp [post]
func (h *AuthPolicyHandler) UpdateSMTP(w http.ResponseWriter, r *http.Request) {
	h.projectSMTP(w, r, true)
}

func (h *AuthPolicyHandler) projectSMTP(w http.ResponseWriter, r *http.Request, update bool) {
	actor, ok := catalog.RequestActor(w, r)
	if !ok {
		return
	}
	_, target, ok := catalog.DirectoryQuery(w, r)
	if !ok {
		return
	}
	if h.delivery == nil {
		h.respondError(w, r, domain.ErrUnavailable)
		return
	}
	var result settings.SMTPSnapshot
	var err error
	if update {
		var input ProjectSMTPRequest
		if err := httpx.DecodeJSON(w, r, &input); err != nil || input.Config == nil {
			httpx.Error(w, 400, "invalid_request", "SMTP configuration required")
			return
		}
		result, err = h.delivery.UpdateProjectSMTP(r.Context(), actor, target, smtp.SMTPUpdateInput{ExpectedVersion: input.ExpectedVersion, Config: *input.Config, Password: input.Password})
	} else {
		result, err = h.delivery.ReadProjectSMTP(r.Context(), actor, target)
	}
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, result)
}

// @Summary Read project login provider settings
// @Tags Platform Projects
// @Param provider path string true "google or telegram"
// @Success 200 {object} settings.ProviderSnapshot
// @Param id path string true "Project UUID"
// @Param expectedVersion query int true "Current project version"
// @Param expectedGeneration query int true "Current project generation"
// @Security SessionCookie
// @ID getPlatformProjectsByIdAuthSettingsProvidersByProvider
// @Router /api/v1/platform/projects/{id}/auth/settings/providers/{provider} [get]
func (h *AuthPolicyHandler) ReadProvider(w http.ResponseWriter, r *http.Request) {
	h.projectProvider(w, r, false)
}

// @Summary Update project login provider settings
// @Tags Platform Projects
// @Param provider path string true "google or telegram"
// @Param body body ProjectProviderRequest true "Client ID and optional replacement secret"
// @Success 200 {object} settings.ProviderSnapshot
// @Param id path string true "Project UUID"
// @Param expectedVersion query int true "Current project version"
// @Param expectedGeneration query int true "Current project generation"
// @Security SessionCookie
// @ID postPlatformProjectsByIdAuthSettingsProvidersByProvider
// @Router /api/v1/platform/projects/{id}/auth/settings/providers/{provider} [post]
func (h *AuthPolicyHandler) UpdateProvider(w http.ResponseWriter, r *http.Request) {
	h.projectProvider(w, r, true)
}

func (h *AuthPolicyHandler) projectProvider(w http.ResponseWriter, r *http.Request, update bool) {
	actor, ok := catalog.RequestActor(w, r)
	if !ok {
		return
	}
	_, target, ok := catalog.DirectoryQuery(w, r)
	if !ok {
		return
	}
	if h.delivery == nil {
		h.respondError(w, r, domain.ErrUnavailable)
		return
	}
	name := chi.URLParam(r, "provider")
	var result settings.ProviderSnapshot
	var err error
	if update {
		var input ProjectProviderRequest
		if err := httpx.DecodeJSON(w, r, &input); err != nil {
			httpx.Error(w, 400, "invalid_json", "invalid JSON")
			return
		}
		result, err = h.delivery.UpdateProjectProvider(r.Context(), actor, target, providers.ProviderUpdateInput{Provider: name, ClientID: input.ClientID, ExpectedVersion: input.ExpectedVersion, Secret: input.Secret})
	} else {
		result, err = h.delivery.ReadProjectProvider(r.Context(), actor, target, name)
	}
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, result)
}
