package http

import (
	"context"
	"net/http"

	operators "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectpg "github.com/Inforberi/financial-intelligence/internal/admin/projects/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type DeletionPreview func(context.Context, operators.Principal, domain.DirectoryTarget) (projectpg.DeletionPreview, error)

func (h *Handler) WithDeletionPreview(preview DeletionPreview) *Handler {
	h.deletionPreview = preview
	return h
}

// @Summary Check whether the selected project has users before deletion
// @Tags Platform Projects
// @Param id path string true "Project UUID"
// @Param expectedVersion query int true "Current project version"
// @Param expectedGeneration query int true "Current project generation"
// @Success 200 {object} projectpg.DeletionPreview
// @Security SessionCookie
// @ID getPlatformProjectsByIdDeletionPreview
// @Router /api/v1/platform/projects/{id}/deletion-preview [get]
func (h *Handler) PreviewDeletion(w http.ResponseWriter, r *http.Request) {
	actor, ok := RequestActor(w, r)
	if !ok {
		return
	}
	_, target, ok := DirectoryQuery(w, r)
	if !ok {
		return
	}
	if h.deletionPreview == nil {
		h.respondError(w, r, domain.ErrUnavailable)
		return
	}
	result, err := h.deletionPreview(r.Context(), actor, target)
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, result)
}
