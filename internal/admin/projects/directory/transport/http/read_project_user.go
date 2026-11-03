package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	cataloghttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

// @Summary Read a project user and current role assignments from the platform
// @Description Requires BOTH current platform.project_users.manage and platform.project_access.manage plus fresh password/MFA before read and before disclosure. Exact ready/enabled project target. Same read-only snapshot for account, contacts and role metadata/accessVersion; no secrets or fabricated project actor. Retained soft-deleted accounts are readable by UUID but not restored. Contacts/providers/roles overflow returns conflict, never partial success. Use role/access versions in subsequent explicit grant/revoke calls.
// @Tags Platform Users
// @Produce json
// @Param id path string true "Project UUID"
// @Param userId path string true "Project user UUID"
// @Param expectedVersion query int true "Current project version"
// @Param expectedGeneration query int true "Current project generation"
// @Success 200 {object} accounthttp.UserDetailResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 404 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 428 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/platform/projects/{id}/users/{userId} [get]
func (h *UserHandler) Read(w http.ResponseWriter, r *http.Request) {
	actor, ok := cataloghttp.RequestActor(w, r)
	if !ok || !cataloghttp.EmptyRequestBody(w, r) {
		return
	}
	_, target, ok := cataloghttp.DirectoryQuery(w, r)
	if !ok {
		return
	}
	user, err := h.service.ReadProjectUser(r.Context(), actor, target, accountdomain.UserID(chi.URLParam(r, "userId")))
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, accounthttp.NewUserDetailResponse(user))
}
