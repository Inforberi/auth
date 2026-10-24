package http

import (
	"net/http"
	"net/url"
	"strconv"

	"github.com/go-chi/chi/v5"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
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
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return invalid()
	}
	for name, items := range values {
		if len(items) != 1 || (name != "expectedVersion" && name != "expectedGeneration" && (!list || (name != "afterKey" && name != "limit"))) {
			return invalid()
		}
	}
	version, err := strconv.ParseInt(values.Get("expectedVersion"), 10, 64)
	if err != nil {
		return invalid()
	}
	generation, err := strconv.ParseInt(values.Get("expectedGeneration"), 10, 64)
	if err != nil {
		return invalid()
	}
	query := service.ProjectRoleQuery{
		Target:   domain.DirectoryTarget{ProjectID: domain.ID(chi.URLParam(r, "id")), ExpectedVersion: version, ExpectedGeneration: generation},
		AfterKey: values.Get("afterKey"), Limit: 50,
	}
	if _, ok := values["limit"]; ok {
		query.Limit, err = strconv.Atoi(values.Get("limit"))
		if err != nil {
			return invalid()
		}
	}
	return query, true
}
