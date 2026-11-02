package http

import (
	"net/http"
	"net/url"
	"slices"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

func DirectoryQuery(w http.ResponseWriter, r *http.Request, allowed ...string) (url.Values, domain.DirectoryTarget, bool) {
	invalid := func() (url.Values, domain.DirectoryTarget, bool) {
		httpx.Error(w, 400, "invalid_query", "invalid query")
		return nil, domain.DirectoryTarget{}, false
	}
	if len(r.URL.RawQuery) > 2048 {
		return invalid()
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return invalid()
	}
	for name, items := range values {
		if len(items) != 1 || (name != "expectedVersion" && name != "expectedGeneration" && !slices.Contains(allowed, name)) {
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
	return values, domain.DirectoryTarget{ProjectID: domain.ID(chi.URLParam(r, "id")), ExpectedVersion: version, ExpectedGeneration: generation}, true
}
