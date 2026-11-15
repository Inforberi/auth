package http

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"

	operators "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type PreparationOperations interface {
	RequestPreparation(context.Context, operators.Principal, domain.PreparationRequest) (domain.PreparationOperation, error)
	ReadPreparation(context.Context, operators.Principal, domain.ID, domain.ID) (domain.PreparationOperation, error)
}

func (h *Handler) WithPreparation(backend PreparationOperations) *Handler {
	h.preparation = backend
	return h
}

type PreparationRequest struct {
	OperationID        domain.ID `json:"operationId" swaggertype:"string"`
	ExpectedVersion    int64     `json:"expectedVersion"`
	ExpectedGeneration int64     `json:"expectedGeneration"`
} // @name project_http.PreparationRequest

// @Summary Request project database preparation
// @Tags Platform Projects
// @Param id path string true "Project UUID"
// @Param body body PreparationRequest true "Operation UUID and project versions"
// @Success 202 {object} domain.PreparationOperation
// @Security SessionCookie
// @ID postPlatformProjectsByIdPreparation
// @Router /api/v1/platform/projects/{id}/preparation [post]
func (h *Handler) RequestPreparation(w http.ResponseWriter, r *http.Request) {
	actor, ok := RequestActor(w, r)
	if !ok {
		return
	}
	var input PreparationRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	if h.preparation == nil {
		h.respondError(w, r, domain.ErrUnavailable)
		return
	}
	project := domain.ID(chi.URLParam(r, "id"))
	result, err := h.preparation.RequestPreparation(r.Context(), actor, domain.PreparationRequest{
		ProjectID: project, OperationID: input.OperationID, ExpectedVersion: input.ExpectedVersion, ExpectedGeneration: input.ExpectedGeneration,
	})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/platform/projects/"+string(project)+"/preparation/"+string(result.OperationID))
	httpx.JSON(w, http.StatusAccepted, result)
}

// @Summary Read project database preparation result
// @Tags Platform Projects
// @Param id path string true "Project UUID"
// @Param operationId path string true "Operation UUID"
// @Success 200 {object} domain.PreparationOperation
// @Security SessionCookie
// @ID getPlatformProjectsByIdPreparationByOperationId
// @Router /api/v1/platform/projects/{id}/preparation/{operationId} [get]
func (h *Handler) ReadPreparation(w http.ResponseWriter, r *http.Request) {
	actor, ok := RequestActor(w, r)
	if !ok {
		return
	}
	if h.preparation == nil {
		h.respondError(w, r, domain.ErrUnavailable)
		return
	}
	result, err := h.preparation.ReadPreparation(r.Context(), actor, domain.ID(chi.URLParam(r, "id")), domain.ID(chi.URLParam(r, "operationId")))
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, result)
}
