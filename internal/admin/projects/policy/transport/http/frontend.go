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

type ProjectFrontends interface {
	ReadProjectFrontends(context.Context, operators.Principal, domain.DirectoryTarget) (policy.FrontendSettings, error)
	UpdateProjectFrontends(context.Context, operators.Principal, domain.DirectoryTarget, int64, settings.FrontendPolicy) (policy.FrontendSettings, error)
}

type ProjectFrontendsRequest struct {
	ExpectedVersion int64                    `json:"expectedVersion"`
	Policy          *settings.FrontendPolicy `json:"policy"`
} // @name project_http.ProjectFrontendsRequest

func (h *AuthPolicyHandler) WithProjectFrontends(backend ProjectFrontends) *AuthPolicyHandler {
	h.frontend = backend
	return h
}

// @Summary Read project frontend policy
// @Tags Platform Projects
// @Param id path string true "Project UUID"
// @Param expectedVersion query int true "Current project version"
// @Param expectedGeneration query int true "Current project generation"
// @Success 200 {object} policy.FrontendSettings
// @Security SessionCookie
// @ID getPlatformProjectsByIdAuthSettingsFrontend
// @Router /api/v1/platform/projects/{id}/auth/settings/frontend [get]
func (h *AuthPolicyHandler) ReadFrontends(w http.ResponseWriter, r *http.Request) {
	h.projectFrontends(w, r, false)
}

// @Summary Update project frontend origins and action URLs
// @Tags Platform Projects
// @Param id path string true "Project UUID"
// @Param expectedVersion query int true "Current project version"
// @Param expectedGeneration query int true "Current project generation"
// @Param body body ProjectFrontendsRequest true "Complete policy and current policy version"
// @Success 200 {object} policy.FrontendSettings
// @Security SessionCookie
// @ID postPlatformProjectsByIdAuthSettingsFrontend
// @Router /api/v1/platform/projects/{id}/auth/settings/frontend [post]
func (h *AuthPolicyHandler) UpdateFrontends(w http.ResponseWriter, r *http.Request) {
	h.projectFrontends(w, r, true)
}

func (h *AuthPolicyHandler) projectFrontends(w http.ResponseWriter, r *http.Request, update bool) {
	actor, ok := catalog.RequestActor(w, r)
	if !ok {
		return
	}
	_, target, ok := catalog.DirectoryQuery(w, r)
	if !ok {
		return
	}
	if h.frontend == nil {
		h.respondError(w, r, domain.ErrUnavailable)
		return
	}
	var result policy.FrontendSettings
	var err error
	if update {
		var input ProjectFrontendsRequest
		if err := httpx.DecodeJSON(w, r, &input); err != nil || input.Policy == nil {
			httpx.Error(w, 400, "invalid_request", "frontend policy required")
			return
		}
		result, err = h.frontend.UpdateProjectFrontends(r.Context(), actor, target, input.ExpectedVersion, *input.Policy)
	} else {
		result, err = h.frontend.ReadProjectFrontends(r.Context(), actor, target)
	}
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, result)
}
