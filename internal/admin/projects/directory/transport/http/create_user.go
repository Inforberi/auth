package http

import (
	"context"
	"net/http"
	"time"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	cataloghttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type CreateUserCommand struct {
	OperationID            domain.ID `json:"operationId" swaggertype:"string"`
	InvitationEmail        string    `json:"invitationEmail,omitempty"`
	TemporaryPasswordEmail string    `json:"temporaryPasswordEmail,omitempty"`
} // @name project_user_http.CreateUserCommand

type CreateUserReceipt struct {
	UserID            accountdomain.UserID `json:"userId" swaggertype:"string"`
	TemporaryPassword string               `json:"temporaryPassword,omitempty"`
	ExpiresAt         *time.Time           `json:"expiresAt,omitempty"`
} // @name project_user_http.CreateUserReceipt

type CreateUser func(context.Context, operatordomain.Principal, domain.DirectoryTarget, CreateUserCommand) (CreateUserReceipt, error)

func (h *UserHandler) WithCreation(run CreateUser) *UserHandler {
	h.createUser = run
	return h
}

// @Summary Create a pending account in a project
// @Tags Platform Users
// @Param id path string true "Project UUID"
// @Param expectedVersion query int true "Current project version"
// @Param expectedGeneration query int true "Current project generation"
// @Description Accepts at most one of invitationEmail and temporaryPasswordEmail. A generated temporary password is returned once on first commit and must not be logged or cached. It requires password replacement and does not verify the email.
// @Param body body CreateUserCommand true "Operation UUID and optional credential delivery mode"
// @Success 200 {object} CreateUserReceipt
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Security SessionCookie
// @ID postPlatformProjectsByIdUsers
// @Router /api/v1/platform/projects/{id}/users [post]
func (h *UserHandler) Create(w http.ResponseWriter, r *http.Request) {
	actor, ok := cataloghttp.RequestActor(w, r)
	if !ok {
		return
	}
	_, target, ok := cataloghttp.DirectoryQuery(w, r)
	if !ok {
		return
	}
	var command CreateUserCommand
	if err := httpx.DecodeJSON(w, r, &command); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	if h.createUser == nil {
		h.respondError(w, r, domain.ErrUnavailable)
		return
	}
	receipt, err := h.createUser(r.Context(), actor, target, command)
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.JSON(w, 200, receipt)
}
