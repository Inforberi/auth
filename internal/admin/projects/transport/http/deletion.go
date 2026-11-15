package http

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"

	operators "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type DeletionOperations interface {
	ConfirmDeletion(context.Context, operators.Principal, domain.DeletionRequest) (domain.DeletionOperation, error)
	ReadDeletion(context.Context, operators.Principal, domain.ID, domain.ID) (domain.DeletionOperation, error)
}

func (h *Handler) WithDeletion(backend DeletionOperations) *Handler {
	h.deletion = backend
	return h
}

type DeletionConfirmation struct {
	PreparationRequest
	ConfirmProject   domain.ID `json:"confirmProjectId" swaggertype:"string"`
	ConfirmLoss      bool      `json:"confirmDataLoss"`
	AcknowledgeUsers bool      `json:"acknowledgeUsers"`
} // @name project_http.DeletionConfirmation

// @Summary Confirm physical deletion of a project
// @Tags Platform Projects
// @Param id path string true "Project UUID"
// @Param body body DeletionConfirmation true "Exact project ID, versions and explicit data loss confirmation"
// @Success 202 {object} domain.DeletionOperation
// @Security SessionCookie
// @ID postPlatformProjectsByIdDeletion
// @Router /api/v1/platform/projects/{id}/deletion [post]
func (h *Handler) ConfirmDeletion(w http.ResponseWriter, r *http.Request) {
	actor, ok := RequestActor(w, r)
	if !ok {
		return
	}
	var body DeletionConfirmation
	if err := httpx.DecodeJSON(w, r, &body); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	if h.deletion == nil {
		h.respondError(w, r, domain.ErrUnavailable)
		return
	}
	project := domain.ID(chi.URLParam(r, "id"))
	result, err := h.deletion.ConfirmDeletion(r.Context(), actor, domain.DeletionRequest{
		Target:      domain.DirectoryTarget{ProjectID: project, ExpectedVersion: body.ExpectedVersion, ExpectedGeneration: body.ExpectedGeneration},
		OperationID: body.OperationID, ConfirmProject: body.ConfirmProject, ConfirmLoss: body.ConfirmLoss, AcknowledgeUsers: body.AcknowledgeUsers,
	})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/platform/projects/"+string(project)+"/deletion/"+string(result.OperationID))
	httpx.JSON(w, http.StatusAccepted, result)
}

// @Summary Read a confirmed project deletion
// @Tags Platform Projects
// @Param id path string true "Project UUID"
// @Param operationId path string true "Operation UUID"
// @Success 200 {object} domain.DeletionOperation
// @Security SessionCookie
// @ID getPlatformProjectsByIdDeletionByOperationId
// @Router /api/v1/platform/projects/{id}/deletion/{operationId} [get]
func (h *Handler) ReadDeletion(w http.ResponseWriter, r *http.Request) {
	actor, ok := RequestActor(w, r)
	if !ok {
		return
	}
	if h.deletion == nil {
		h.respondError(w, r, domain.ErrUnavailable)
		return
	}
	result, err := h.deletion.ReadDeletion(r.Context(), actor, domain.ID(chi.URLParam(r, "id")), domain.ID(chi.URLParam(r, "operationId")))
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, result)
}
