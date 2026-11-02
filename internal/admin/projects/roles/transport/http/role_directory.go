package http

import (
	"net/http"
	"strconv"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	roleservice "github.com/Inforberi/financial-intelligence/internal/admin/projects/roles/service"
	cataloghttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type PlatformRoleSummary struct {
	ID          accessdomain.RoleID `json:"id" swaggertype:"string"`
	Key         string              `json:"key"`
	Name        string              `json:"name"`
	Description string              `json:"description"`
	System      bool                `json:"system"`
	MFARequired bool                `json:"mfaRequired"`
	Version     int64               `json:"version"`
} // @name project_http.PlatformRoleSummary

func roleDirectoryQuery(w http.ResponseWriter, r *http.Request, list bool) (roleservice.ProjectRoleQuery, bool) {
	invalid := func() (roleservice.ProjectRoleQuery, bool) {
		httpx.Error(w, 400, "invalid_query", "invalid query")
		return roleservice.ProjectRoleQuery{}, false
	}
	if len(r.URL.RawQuery) > 1024 {
		return invalid()
	}
	var allowed []string
	if list {
		allowed = []string{"afterKey", "limit"}
	}
	values, target, ok := cataloghttp.DirectoryQuery(w, r, allowed...)
	if !ok {
		return roleservice.ProjectRoleQuery{}, false
	}
	query := roleservice.ProjectRoleQuery{Target: target, AfterKey: values.Get("afterKey"), Limit: 50}
	if _, ok := values["limit"]; ok {
		limit, err := strconv.Atoi(values.Get("limit"))
		if err != nil {
			return invalid()
		}
		query.Limit = limit
	}
	return query, true
}
