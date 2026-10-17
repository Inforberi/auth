package http

import (
	"net/http"
	"net/url"
	"strconv"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type RoleSummaryResponse struct {
	ID          domain.RoleID `json:"id" swaggertype:"string"`
	Key         string        `json:"key"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	System      bool          `json:"system"`
	MFARequired bool          `json:"mfaRequired"`
	Version     int64         `json:"version"`
} // @name access_http.RoleSummaryResponse

type RolePageResponse struct {
	Roles     []RoleSummaryResponse `json:"roles"`
	NextAfter string                `json:"nextAfter"`
} // @name access_http.RolePageResponse

// @Summary List role metadata
// @Description Requires current roles.manage or assignments.manage. Keyset pagination, no count or per-role permission queries. A full page returns its last key as nextAfter; a final empty page may be necessary. Use role detail for permissions.
// @Tags Admin Access
// @Produce json
// @Param after query string false "Exclusive last role key"
// @Param limit query int false "Page size, 1..100, default 50" default(50)
// @Success 200 {object} RolePageResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/admin/roles [get]
func (h *Handler) ListRoles(w http.ResponseWriter, r *http.Request) {
	actor, ok := principal(w, r)
	if !ok {
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		httpx.Error(w, 400, "invalid_query", "invalid query")
		return
	}
	for key, values := range query {
		if (key != "after" && key != "limit") || len(values) != 1 {
			httpx.Error(w, 400, "invalid_query", "invalid query")
			return
		}
	}
	limit := 50
	if raw, exists := query["limit"]; exists {
		limit, err = strconv.Atoi(raw[0])
		if err != nil {
			httpx.Error(w, 400, "invalid_query", "invalid query")
			return
		}
	}
	roles, err := h.service.ListManagedRoles(r.Context(), actor, query.Get("after"), limit)
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	page := RolePageResponse{Roles: make([]RoleSummaryResponse, 0, len(roles))}
	for _, role := range roles {
		page.Roles = append(page.Roles, RoleSummaryResponse{ID: role.ID, Key: role.Key, Name: role.Name, Description: role.Description, System: role.System, Version: role.Version, MFARequired: role.MFARequired})
	}
	if len(roles) == limit {
		page.NextAfter = roles[len(roles)-1].Key
	}
	httpx.JSON(w, 200, page)
}
