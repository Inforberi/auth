package http

import (
	"net/http"
	"strconv"

	cataloghttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

// @Summary List users of an independent project from the platform
// @Description Requires current platform.project_users.manage and fresh password/MFA before read and before disclosure. Exact ready/enabled project binding and version/generation. Read-only snapshot, nondeleted users only, exact normalized email/status filters, exclusive createdAt/UUID cursor. No offset, total count, project session, admission or session renewal. Returns no roles or credential secrets.
// @Tags Platform Users
// @Produce json
// @Param id path string true "Project UUID"
// @Param expectedVersion query int true "Current project version"
// @Param expectedGeneration query int true "Current project generation"
// @Param before query string false "Opaque nextCursor from previous page"
// @Param status query string false "Account status" Enums(pending,active,blocked)
// @Param email query string false "Exact email, not substring search"
// @Param limit query int false "Page size 1..100, default 50" default(50)
// @Success 200 {object} accounthttp.UserPageResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 428 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/platform/projects/{id}/users [get]
func (h *UserHandler) List(w http.ResponseWriter, r *http.Request) {
	actor, ok := cataloghttp.RequestActor(w, r)
	if !ok || !cataloghttp.EmptyRequestBody(w, r) {
		return
	}
	values, target, ok := cataloghttp.DirectoryQuery(w, r, "before", "status", "email", "limit")
	if !ok {
		return
	}
	input := accountservice.UserListInput{Before: values.Get("before"), Status: accountdomain.Status(values.Get("status")), Email: values.Get("email"), Limit: 50}
	if _, ok := values["limit"]; ok {
		limit, err := strconv.Atoi(values.Get("limit"))
		if err != nil {
			httpx.Error(w, 400, "invalid_query", "invalid query")
			return
		}
		input.Limit = limit
	}
	page, err := h.service.ListProjectUsers(r.Context(), actor, target, input)
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	response := accounthttp.UserPageResponse{Users: make([]accounthttp.UserSummaryResponse, 0, len(page.Users)), NextCursor: page.NextCursor}
	for _, user := range page.Users {
		response.Users = append(response.Users, accounthttp.NewUserSummaryResponse(user))
	}
	httpx.JSON(w, 200, response)
}
