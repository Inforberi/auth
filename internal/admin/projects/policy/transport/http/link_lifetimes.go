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

type ProjectLinkLifetimes interface {
	ReadProjectLinkLifetimes(context.Context, operators.Principal, domain.DirectoryTarget) (policy.LinkLifetimeSettings, error)
	UpdateProjectLinkLifetimes(context.Context, operators.Principal, domain.DirectoryTarget, int64, settings.LinkLifetimePolicy) (policy.LinkLifetimeSettings, error)
}

type ProjectLinkLifetimesRequest struct {
	ExpectedVersion int64                        `json:"expectedVersion"`
	Policy          *settings.LinkLifetimePolicy `json:"policy"`
} // @name project_http.ProjectLinkLifetimesRequest

func (h *AuthPolicyHandler) WithProjectLinkLifetimes(backend ProjectLinkLifetimes) *AuthPolicyHandler {
	h.linkLifetimes = backend
	return h
}

// @Summary Read project link lifetime policy
// @Tags Platform Projects
// @Param id path string true "Project UUID"
// @Param expectedVersion query int true "Current project version"
// @Param expectedGeneration query int true "Current project generation"
// @Success 200 {object} policy.LinkLifetimeSettings
// @Security SessionCookie
// @ID getPlatformProjectsByIdAuthSettingsLinkLifetimes
// @Router /api/v1/platform/projects/{id}/auth/settings/link-lifetimes [get]
func (h *AuthPolicyHandler) ReadLinkLifetimes(w http.ResponseWriter, r *http.Request) {
	h.projectLinkLifetimes(w, r, false)
}

// @Summary Update project lifetimes for new verification and reset links
// @Tags Platform Projects
// @Param id path string true "Project UUID"
// @Param expectedVersion query int true "Current project version"
// @Param expectedGeneration query int true "Current project generation"
// @Param body body ProjectLinkLifetimesRequest true "Complete policy and current policy version"
// @Success 200 {object} policy.LinkLifetimeSettings
// @Security SessionCookie
// @ID postPlatformProjectsByIdAuthSettingsLinkLifetimes
// @Router /api/v1/platform/projects/{id}/auth/settings/link-lifetimes [post]
func (h *AuthPolicyHandler) UpdateLinkLifetimes(w http.ResponseWriter, r *http.Request) {
	h.projectLinkLifetimes(w, r, true)
}

func (h *AuthPolicyHandler) projectLinkLifetimes(w http.ResponseWriter, r *http.Request, update bool) {
	actor, ok := catalog.RequestActor(w, r)
	if !ok {
		return
	}
	_, target, ok := catalog.DirectoryQuery(w, r)
	if !ok {
		return
	}
	if h.linkLifetimes == nil {
		h.respondError(w, r, domain.ErrUnavailable)
		return
	}
	var result policy.LinkLifetimeSettings
	var err error
	if update {
		var input ProjectLinkLifetimesRequest
		if err := httpx.DecodeJSON(w, r, &input); err != nil || input.Policy == nil {
			httpx.Error(w, 400, "invalid_request", "link lifetime policy required")
			return
		}
		result, err = h.linkLifetimes.UpdateProjectLinkLifetimes(r.Context(), actor, target, input.ExpectedVersion, *input.Policy)
	} else {
		result, err = h.linkLifetimes.ReadProjectLinkLifetimes(r.Context(), actor, target)
	}
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, result)
}
