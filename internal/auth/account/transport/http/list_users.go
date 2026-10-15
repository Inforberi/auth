package http

import (
	"net/http"
	"net/url"
	"strconv"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type UserPageResponse struct {
	Users      []UserSummaryResponse `json:"users"`
	NextCursor string                `json:"nextCursor"`
} // @name account_http.UserPageResponse

// @Summary List users
// @Description Requires current accounts.users.read and SQL session; no fresh password/MFA or session renewal for this read. Newest createdAt/UUID first, exclusive cursor, nondeleted users only. Exact normalized email and optional status filters, no substring search, offset or total count. Selected display email prefers password contact, otherwise first retained contact by UUID. One bounded SQL statement checks permission and reads a page.
// @Tags Admin Users
// @Produce json
// @Param before query string false "Opaque exclusive nextCursor from the previous page"
// @Param status query string false "Account status" Enums(pending,active,blocked)
// @Param email query string false "Exact email, not a substring"
// @Param limit query int false "Page size 1..100, default 50" default(50)
// @Success 200 {object} UserPageResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/admin/users [get]
func (h *UserDirectoryHandler) List(w http.ResponseWriter, r *http.Request) {
	actor, ok := accountActor(w, r)
	if !ok {
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		httpx.Error(w, 400, "invalid_query", "invalid query")
		return
	}
	for name, values := range query {
		if len(values) != 1 || (name != "before" && name != "status" && name != "email" && name != "limit") {
			httpx.Error(w, 400, "invalid_query", "invalid query")
			return
		}
	}
	limit := 50
	if values, ok := query["limit"]; ok {
		limit, err = strconv.Atoi(values[0])
		if err != nil {
			httpx.Error(w, 400, "invalid_query", "invalid query")
			return
		}
	}
	page, err := h.service.List(r.Context(), actor, service.UserListInput{Before: query.Get("before"), Status: domain.Status(query.Get("status")), Email: query.Get("email"), Limit: limit})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	response := UserPageResponse{Users: make([]UserSummaryResponse, 0, len(page.Users)), NextCursor: page.NextCursor}
	for _, user := range page.Users {
		response.Users = append(response.Users, userSummaryResponse(user))
	}
	httpx.JSON(w, 200, response)
}
