package http

import (
	"net/http"
	"strconv"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/service"
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

func roleDirectoryQuery(w http.ResponseWriter, r *http.Request, list bool) (service.ProjectRoleQuery, bool) {
	invalid := func() (service.ProjectRoleQuery, bool) {
		httpx.Error(w, 400, "invalid_query", "invalid query")
		return service.ProjectRoleQuery{}, false
	}
	if len(r.URL.RawQuery) > 1024 {
		return invalid()
	}
	var allowed []string
	if list {
		allowed = []string{"afterKey", "limit"}
	}
	values, target, ok := directoryQuery(w, r, allowed...)
	if !ok {
		return service.ProjectRoleQuery{}, false
	}
	query := service.ProjectRoleQuery{Target: target, AfterKey: values.Get("afterKey"), Limit: 50}
	if _, ok := values["limit"]; ok {
		limit, err := strconv.Atoi(values.Get("limit"))
		if err != nil {
			return invalid()
		}
		query.Limit = limit
	}
	return query, true
}
