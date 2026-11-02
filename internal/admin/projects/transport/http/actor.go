package http

import (
	"io"
	"net/http"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

func OperationActor(w http.ResponseWriter, r *http.Request) (operatordomain.Principal, bool) {
	actor, ok := RequestActor(w, r)
	if !ok {
		return actor, false
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		httpx.Error(w, 400, "invalid_query", "query parameters are not supported")
		return actor, false
	}
	return actor, true
}

func EmptyRequestBody(w http.ResponseWriter, r *http.Request) bool {
	if r.Body == nil {
		return true
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 1))
	if err != nil || len(data) != 0 {
		httpx.Error(w, 400, "invalid_body", "request body must be empty")
		return false
	}
	return true
}
