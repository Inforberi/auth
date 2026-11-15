package http

import (
	"context"
	"net/http"

	operators "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	policy "github.com/Inforberi/financial-intelligence/internal/admin/projects/policy/repository/postgres"
	catalog "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	settings "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type ProjectCredentialLifetimes interface {
	ReadProjectCredentialLifetimes(context.Context, operators.Principal, domain.DirectoryTarget) (policy.CredentialLifetimeSettings, error)
	UpdateProjectCredentialLifetimes(context.Context, operators.Principal, domain.DirectoryTarget, int64, settings.CredentialLifetimePolicy) (policy.CredentialLifetimeSettings, error)
}

type ProjectCredentialLifetimesRequest struct {
	ExpectedVersion int64                              `json:"expectedVersion"`
	Policy          *settings.CredentialLifetimePolicy `json:"policy"`
} // @name project_http.ProjectCredentialLifetimesRequest

func (h *AuthPolicyHandler) WithProjectCredentialLifetimes(backend ProjectCredentialLifetimes) *AuthPolicyHandler {
	h.credentialLifetimes = backend
	return h
}

// @Summary Read project credential lifetime policy
// @Tags Platform Projects
// @Param id path string true "Project UUID"
// @Param expectedVersion query int true "Current project version"
// @Param expectedGeneration query int true "Current project generation"
// @Success 200 {object} policy.CredentialLifetimeSettings
// @Security SessionCookie
// @ID getPlatformProjectsByIdAuthSettingsCredentialLifetimes
// @Router /api/v1/platform/projects/{id}/auth/settings/credential-lifetimes [get]
func (h *AuthPolicyHandler) ReadCredentialLifetimes(w http.ResponseWriter, r *http.Request) {
	h.projectCredentialLifetimes(w, r, false)
}

// @Summary Update project lifetimes for new authentication credentials
// @Tags Platform Projects
// @Param id path string true "Project UUID"
// @Param expectedVersion query int true "Current project version"
// @Param expectedGeneration query int true "Current project generation"
// @Param body body ProjectCredentialLifetimesRequest true "Complete policy and current policy version"
// @Success 200 {object} policy.CredentialLifetimeSettings
// @Security SessionCookie
// @ID postPlatformProjectsByIdAuthSettingsCredentialLifetimes
// @Router /api/v1/platform/projects/{id}/auth/settings/credential-lifetimes [post]
func (h *AuthPolicyHandler) UpdateCredentialLifetimes(w http.ResponseWriter, r *http.Request) {
	h.projectCredentialLifetimes(w, r, true)
}

func (h *AuthPolicyHandler) projectCredentialLifetimes(w http.ResponseWriter, r *http.Request, update bool) {
	actor, ok := catalog.RequestActor(w, r)
	if !ok {
		return
	}
	_, target, ok := catalog.DirectoryQuery(w, r)
	if !ok {
		return
	}
	if h.credentialLifetimes == nil {
		h.respondError(w, r, domain.ErrUnavailable)
		return
	}
	var result policy.CredentialLifetimeSettings
	var err error
	if update {
		var input ProjectCredentialLifetimesRequest
		if err := httpx.DecodeJSON(w, r, &input); err != nil || input.Policy == nil {
			httpx.Error(w, 400, "invalid_request", "credential lifetime policy required")
			return
		}
		result, err = h.credentialLifetimes.UpdateProjectCredentialLifetimes(r.Context(), actor, target, input.ExpectedVersion, *input.Policy)
	} else {
		result, err = h.credentialLifetimes.ReadProjectCredentialLifetimes(r.Context(), actor, target)
	}
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, result)
}
