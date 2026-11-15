package http

import (
	"context"
	"net/http"

	operators "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	catalog "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	settings "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	retention "github.com/Inforberi/financial-intelligence/internal/auth/settings/retention/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type ProjectRetention interface {
	ReadProjectRetention(context.Context, operators.Principal, domain.DirectoryTarget) (settings.RetentionSnapshot, error)
	UpdateProjectRetention(context.Context, operators.Principal, domain.DirectoryTarget, retention.RetentionUpdateInput) (settings.RetentionSnapshot, error)
}

func (h *AuthPolicyHandler) WithProjectRetention(backend ProjectRetention) *AuthPolicyHandler {
	h.retention = backend
	return h
}

type ProjectRetentionRequest struct {
	ExpectedVersion   int64                    `json:"expectedVersion"`
	Policy            settings.RetentionPolicy `json:"policy"`
	ConfirmShortening bool                     `json:"confirmShortening"`
} // @name project_http.ProjectRetentionRequest

// @Summary Read project data retention settings
// @Tags Platform Projects
// @Param id path string true "Project UUID"
// @Param expectedVersion query int true "Current project version"
// @Param expectedGeneration query int true "Current project generation"
// @Success 200 {object} settings.RetentionSnapshot
// @Security SessionCookie
// @ID getPlatformProjectsByIdAuthSettingsRetention
// @Router /api/v1/platform/projects/{id}/auth/settings/retention [get]
func (h *AuthPolicyHandler) ReadRetention(w http.ResponseWriter, r *http.Request) {
	h.projectRetention(w, r, false)
}

// @Summary Update project data retention settings
// @Tags Platform Projects
// @Param id path string true "Project UUID"
// @Param expectedVersion query int true "Current project version"
// @Param expectedGeneration query int true "Current project generation"
// @Param body body ProjectRetentionRequest true "Retention policy, current version and shortening confirmation"
// @Success 200 {object} settings.RetentionSnapshot
// @Security SessionCookie
// @ID postPlatformProjectsByIdAuthSettingsRetention
// @Router /api/v1/platform/projects/{id}/auth/settings/retention [post]
func (h *AuthPolicyHandler) UpdateRetention(w http.ResponseWriter, r *http.Request) {
	h.projectRetention(w, r, true)
}

func (h *AuthPolicyHandler) projectRetention(w http.ResponseWriter, r *http.Request, update bool) {
	actor, ok := catalog.RequestActor(w, r)
	if !ok {
		return
	}
	_, target, ok := catalog.DirectoryQuery(w, r)
	if !ok {
		return
	}
	if h.retention == nil {
		h.respondError(w, r, domain.ErrUnavailable)
		return
	}
	var result settings.RetentionSnapshot
	var err error
	if update {
		var input ProjectRetentionRequest
		if err := httpx.DecodeJSON(w, r, &input); err != nil {
			httpx.Error(w, 400, "invalid_json", "invalid JSON")
			return
		}
		result, err = h.retention.UpdateProjectRetention(r.Context(), actor, target, retention.RetentionUpdateInput{
			ExpectedVersion: input.ExpectedVersion, Policy: input.Policy, ConfirmShortening: input.ConfirmShortening,
		})
	} else {
		result, err = h.retention.ReadProjectRetention(r.Context(), actor, target)
	}
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, result)
}
