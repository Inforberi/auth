package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/access/service"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type AssignmentRequest struct {
	ExpectedRoleVersion   int64 `json:"expectedRoleVersion" binding:"required"`
	ExpectedAccessVersion int64 `json:"expectedAccessVersion" binding:"required"`
} // @name access_http.AssignmentRequest

type AssignmentResponse struct {
	AccessVersion int64 `json:"accessVersion"`
} // @name access_http.AssignmentResponse

func (h *Handler) changeAssignment(w http.ResponseWriter, r *http.Request, grant bool) {
	actor, ok := principal(w, r)
	if !ok {
		return
	}
	var input AssignmentRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	version, err := h.service.ChangeAssignment(r.Context(), service.AssignmentInput{
		Actor: actor, UserID: accountdomain.UserID(chi.URLParam(r, "id")), RoleID: domain.RoleID(chi.URLParam(r, "roleId")),
		ExpectedRoleVersion: input.ExpectedRoleVersion, ExpectedAccessVersion: input.ExpectedAccessVersion, Grant: grant,
	})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, AssignmentResponse{AccessVersion: version})
}
