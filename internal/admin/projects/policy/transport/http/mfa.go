package http

import (
	"context"
	"net/http"

	operators "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	catalog "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	settings "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type ProjectMFA interface {
	ReadProjectMFA(context.Context, operators.Principal, domain.DirectoryTarget) (settings.MFASnapshot, error)
	UpdateProjectMFA(context.Context, operators.Principal, domain.DirectoryTarget, settingsservice.MFAChange) (settings.MFASnapshot, error)
}

func (h *AuthPolicyHandler) WithProjectMFA(backend ProjectMFA) *AuthPolicyHandler {
	h.mfa = backend
	return h
}

type ProjectMFARequest struct {
	ExpectedVersion int64            `json:"expectedVersion"`
	Mode            settings.MFAMode `json:"mode" enums:"optional,administrators,required" swaggertype:"string"`
} // @name project_http.ProjectMFARequest

// @Summary Read project MFA policy
// @Tags Platform Projects
// @Param id path string true "Project UUID"
// @Param expectedVersion query int true "Current project version"
// @Param expectedGeneration query int true "Current project generation"
// @Success 200 {object} settings.MFASnapshot
// @Security SessionCookie
// @ID getPlatformProjectsByIdAuthSettingsMfa
// @Router /api/v1/platform/projects/{id}/auth/settings/mfa [get]
func (h *AuthPolicyHandler) ReadMFA(w http.ResponseWriter, r *http.Request) {
	h.projectMFA(w, r, false)
}

// @Summary Update project MFA policy
// @Tags Platform Projects
// @Param id path string true "Project UUID"
// @Param expectedVersion query int true "Current project version"
// @Param expectedGeneration query int true "Current project generation"
// @Param body body ProjectMFARequest true "MFA mode and current policy version"
// @Success 200 {object} settings.MFASnapshot
// @Security SessionCookie
// @ID postPlatformProjectsByIdAuthSettingsMfa
// @Router /api/v1/platform/projects/{id}/auth/settings/mfa [post]
func (h *AuthPolicyHandler) UpdateMFA(w http.ResponseWriter, r *http.Request) {
	h.projectMFA(w, r, true)
}

func (h *AuthPolicyHandler) projectMFA(w http.ResponseWriter, r *http.Request, update bool) {
	actor, ok := catalog.RequestActor(w, r)
	if !ok {
		return
	}
	_, target, ok := catalog.DirectoryQuery(w, r)
	if !ok {
		return
	}
	if h.mfa == nil {
		h.respondError(w, r, domain.ErrUnavailable)
		return
	}
	var result settings.MFASnapshot
	var err error
	if update {
		var input ProjectMFARequest
		if err := httpx.DecodeJSON(w, r, &input); err != nil {
			httpx.Error(w, 400, "invalid_json", "invalid JSON")
			return
		}
		result, err = h.mfa.UpdateProjectMFA(r.Context(), actor, target, settingsservice.MFAChange{ExpectedVersion: input.ExpectedVersion, Policy: settings.MFAPolicy{Mode: input.Mode}})
	} else {
		result, err = h.mfa.ReadProjectMFA(r.Context(), actor, target)
	}
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, result)
}
