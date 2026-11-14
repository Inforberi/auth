package settingshttp

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type PolicyErrorResponse = httpx.ErrorResponse

func servePolicyRead[V any](w http.ResponseWriter, r *http.Request, read func(context.Context, accessservice.Principal) (V, error), respond func(http.ResponseWriter, *http.Request, V, error)) {
	if actor, ok := Principal(w, r); ok {
		result, err := read(r.Context(), actor)
		respond(w, r, result, err)
	}
}

func servePolicyUpdate[P, V any](w http.ResponseWriter, r *http.Request, update func(context.Context, accessservice.Principal, int64, P) (V, error), respond func(http.ResponseWriter, *http.Request, V, error)) {
	actor, ok := Principal(w, r)
	if !ok {
		return
	}
	var input struct {
		ExpectedVersion int64 `json:"expectedVersion"`
		Policy          *P    `json:"policy"`
	}
	if err := httpx.DecodeJSON(w, r, &input); err != nil || input.Policy == nil || input.ExpectedVersion < 1 {
		httpx.Error(w, 400, "invalid_json", "complete policy and version required")
		return
	}
	result, err := update(r.Context(), actor, input.ExpectedVersion, *input.Policy)
	respond(w, r, result, err)
}

func respondPolicy[V any](w http.ResponseWriter, r *http.Request, log *zap.Logger, kind string, result V, err, invalid error, message string) {
	w.Header().Set("Cache-Control", "no-store")
	if err == nil {
		httpx.JSON(w, 200, result)
		return
	}
	rules := append(SettingsErrorRules(), httpx.MatchError(invalid, 400, "invalid_"+kind, message))
	httpx.RespondError(w, r, log, kind, err, rules, httpx.Failure{Status: 503, Code: "temporarily_unavailable", Message: "temporarily unavailable"})
}

func policyResponse[V any](log *zap.Logger, kind string, invalid error, message string) func(http.ResponseWriter, *http.Request, V, error) {
	return func(w http.ResponseWriter, r *http.Request, result V, err error) {
		respondPolicy(w, r, log, kind, result, err, invalid, message)
	}
}
