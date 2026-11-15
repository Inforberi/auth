package http

import (
	"context"
	"net/http"

	operators "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	policy "github.com/Inforberi/financial-intelligence/internal/admin/projects/policy/repository/postgres"
	catalog "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	sessions "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type ProjectSessions interface {
	ReadProjectSessions(context.Context, operators.Principal, domain.DirectoryTarget) (policy.BrowserSessionSettings, error)
	UpdateProjectSessions(context.Context, operators.Principal, domain.DirectoryTarget, int64, sessions.BrowserPolicy) (policy.BrowserSessionSettings, error)
}

type ProjectSessionsRequest struct {
	ExpectedVersion int64                   `json:"expectedVersion"`
	Policy          *sessions.BrowserPolicy `json:"policy"`
} // @name project_http.ProjectSessionsRequest

func (h *AuthPolicyHandler) WithProjectSessions(backend ProjectSessions) *AuthPolicyHandler {
	h.sessions = backend
	return h
}

// @Summary Read project browser session policy
// @Tags Platform Projects
// @Param id path string true "Project UUID"
// @Param expectedVersion query int true "Current project version"
// @Param expectedGeneration query int true "Current project generation"
// @Success 200 {object} policy.BrowserSessionSettings
// @Security SessionCookie
// @ID getPlatformProjectsByIdAuthSettingsSessions
// @Router /api/v1/platform/projects/{id}/auth/settings/sessions [get]
func (h *AuthPolicyHandler) ReadSessions(w http.ResponseWriter, r *http.Request) {
	h.projectSessions(w, r, false)
}

// @Summary Update project policy for new browser sessions
// @Tags Platform Projects
// @Param id path string true "Project UUID"
// @Param expectedVersion query int true "Current project version"
// @Param expectedGeneration query int true "Current project generation"
// @Param body body ProjectSessionsRequest true "Complete policy and current policy version"
// @Success 200 {object} policy.BrowserSessionSettings
// @Security SessionCookie
// @ID postPlatformProjectsByIdAuthSettingsSessions
// @Router /api/v1/platform/projects/{id}/auth/settings/sessions [post]
func (h *AuthPolicyHandler) UpdateSessions(w http.ResponseWriter, r *http.Request) {
	h.projectSessions(w, r, true)
}

func (h *AuthPolicyHandler) projectSessions(w http.ResponseWriter, r *http.Request, update bool) {
	actor, ok := catalog.RequestActor(w, r)
	if !ok {
		return
	}
	_, target, ok := catalog.DirectoryQuery(w, r)
	if !ok {
		return
	}
	if h.sessions == nil {
		h.respondError(w, r, domain.ErrUnavailable)
		return
	}
	var result policy.BrowserSessionSettings
	var err error
	if update {
		var input ProjectSessionsRequest
		if err := httpx.DecodeJSON(w, r, &input); err != nil || input.Policy == nil {
			httpx.Error(w, 400, "invalid_request", "session policy required")
			return
		}
		result, err = h.sessions.UpdateProjectSessions(r.Context(), actor, target, input.ExpectedVersion, *input.Policy)
	} else {
		result, err = h.sessions.ReadProjectSessions(r.Context(), actor, target)
	}
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, result)
}
