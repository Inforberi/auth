package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type ChangeStateRequest struct {
	OperationID        domain.ID `json:"operationId" swaggertype:"string"`
	ExpectedVersion    int64     `json:"expectedVersion"`
	ExpectedGeneration int64     `json:"expectedGeneration"`
	Reason             string    `json:"reason"`
} // @name project_http.ChangeStateRequest

type TransitionResponse struct {
	ProjectID    domain.ID           `json:"projectId" swaggertype:"string"`
	DesiredState domain.DesiredState `json:"desiredState" swaggertype:"string"`
	Phase        domain.Phase        `json:"phase" swaggertype:"string"`
	Version      int64               `json:"version"`
	Generation   int64               `json:"generation"`
	Replayed     bool                `json:"replayed"`
} // @name project_http.TransitionResponse

func (h *Handler) changeState(w http.ResponseWriter, r *http.Request, action domain.Action) {
	actor, ok := RequestActor(w, r)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		httpx.Error(w, 400, "invalid_query", "invalid project query")
		return
	}
	var input ChangeStateRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	result, err := h.service.ChangeState(r.Context(), actor, action, service.ChangeStateInput{
		ProjectID: domain.ID(chi.URLParam(r, "id")), OperationID: input.OperationID,
		ExpectedVersion: input.ExpectedVersion, ExpectedGeneration: input.ExpectedGeneration, Reason: input.Reason,
	})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, TransitionResponse{
		ProjectID: result.ProjectID, DesiredState: result.DesiredState, Phase: result.Phase,
		Version: result.Version, Generation: result.Generation, Replayed: result.Replayed,
	})
}
