package http

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	cataloghttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type LifecycleCommand struct {
	OperationID domain.ID                 `json:"operationId" swaggertype:"string"`
	AuthVersion accountdomain.AuthVersion `json:"expectedAuthVersion" swaggertype:"integer"`
	Action      string                    `json:"action" enums:"active,blocked,delete,temporary_password,initial_email"`
	Email       string                    `json:"email,omitempty"`
} // @name project_user_http.LifecycleCommand

type LifecycleReceipt struct {
	AuthVersion       accountdomain.AuthVersion `json:"authVersion" swaggertype:"integer"`
	TemporaryPassword string                    `json:"temporaryPassword,omitempty"`
	ExpiresAt         *time.Time                `json:"expiresAt,omitempty"`
} // @name project_user_http.LifecycleReceipt

type Lifecycle func(context.Context, operatordomain.Principal, domain.DirectoryTarget, accountdomain.UserID, LifecycleCommand) (LifecycleReceipt, error)

func (h *UserHandler) WithLifecycle(run Lifecycle) *UserHandler {
	h.lifecycle = run
	return h
}

// @Summary Change the lifecycle of a project user from the platform
// @Tags Platform Users
// @Param id path string true "Project UUID"
// @Param userId path string true "Project user UUID"
// @Param expectedVersion query int true "Current project version"
// @Param expectedGeneration query int true "Current project generation"
// @Param body body LifecycleCommand true "Operation, expected account version and action"
// @Success 200 {object} LifecycleReceipt
// @Failure 409 {object} httpx.ErrorResponse
// @Security SessionCookie
// @ID postPlatformProjectsByIdUsersByUserIdLifecycle
// @Router /api/v1/platform/projects/{id}/users/{userId}/lifecycle [post]
func (h *UserHandler) ChangeLifecycle(w http.ResponseWriter, r *http.Request) {
	actor, ok := cataloghttp.RequestActor(w, r)
	if !ok {
		return
	}
	_, target, ok := cataloghttp.DirectoryQuery(w, r)
	if !ok {
		return
	}
	var command LifecycleCommand
	if err := httpx.DecodeJSON(w, r, &command); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	if h.lifecycle == nil {
		h.respondError(w, r, domain.ErrUnavailable)
		return
	}
	receipt, err := h.lifecycle(r.Context(), actor, target, accountdomain.UserID(chi.URLParam(r, "userId")), command)
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.JSON(w, 200, receipt)
}
