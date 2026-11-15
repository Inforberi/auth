package http

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	cataloghttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type UpdateProjectAuthPolicyRequest struct {
	OperationID           domain.ID                   `json:"operationId" binding:"required" swaggertype:"string"`
	ExpectedVersion       int64                       `json:"expectedVersion" binding:"required"`
	ExpectedGeneration    int64                       `json:"expectedGeneration" binding:"required"`
	ExpectedPolicyVersion int64                       `json:"expectedPolicyVersion" binding:"required"`
	Reason                string                      `json:"reason" binding:"required"`
	Policy                *settingshttp.PolicyRequest `json:"policy" binding:"required" swaggertype:"object"`
} // @name project_http.UpdateProjectAuthPolicyRequest

// @Summary Replace a project's public authentication policy
// @Description Requires current platform.project_settings.manage and fresh password/MFA. Full policy including explicit false values. Project version/generation and policy version prevent stale writes. Current authority commits an exact admission for at most 3 seconds; already admitted work may finish after a later revoke. Project change and platform-attributed receipt/audit commit together, with no fake local user. No-op/replay do not rewrite settings. Methods, stored provider credentials, required delivery and token adapters must be ready; deployment cannot be supplied in the request. Current production bridge rejects enabling unassembled methods. Existing sessions/JWT are not automatically revoked. 202 means unknown commit, not rollback; retry the same operation/payload or read its result. No query parameters. Body at most 8 KiB.
// @Tags Platform Auth settings
// @Accept json
// @Produce json
// @Param id path string true "Project UUID"
// @Param body body UpdateProjectAuthPolicyRequest{policy=settingshttp.PolicyRequest} true "Complete policy, immutable operation and expected versions"
// @Success 200 {object} ProjectAuthPolicyResponse{settings=settingshttp.SettingsResponse}
// @Success 202 {object} ProjectAuthPolicyResponse{settings=settingshttp.SettingsResponse}
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 428 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Security SessionCookie
// @ID postPlatformProjectsByIdAuthSettings
// @Router /api/v1/platform/projects/{id}/auth/settings [post]
func (h *AuthPolicyHandler) Update(w http.ResponseWriter, r *http.Request) {
	actor, ok := cataloghttp.OperationActor(w, r)
	if !ok {
		return
	}
	var input UpdateProjectAuthPolicyRequest
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	policy, ok := input.Policy.Domain()
	if !ok {
		httpx.Error(w, 400, "invalid_json", "complete policy required")
		return
	}
	project := domain.ID(chi.URLParam(r, "id"))
	command := domain.AuthPolicyUpdate{
		OperationID: input.OperationID, ProjectID: project,
		ExpectedVersion: input.ExpectedVersion, ExpectedGeneration: input.ExpectedGeneration, ExpectedPolicyVersion: input.ExpectedPolicyVersion,
		Policy: policy, Reason: input.Reason,
	}
	result, err := h.service.UpdateAuthPolicy(r.Context(), actor, command)
	status, committed := 200, true
	if errors.Is(err, domain.ErrOperationOutcomeUnknown) {
		status, committed = 202, false
	} else if err != nil {
		h.respondError(w, r, err)
		return
	}
	w.Header().Set("Location", policyOperationLocation(project, input.OperationID))
	httpx.JSON(w, status, h.result(input.OperationID, committed, result))
}
