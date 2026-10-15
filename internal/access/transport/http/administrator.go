package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/Inforberi/financial-intelligence/internal/access/service"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type AdministratorRequest struct {
	ExpectedAuthVersion   accountdomain.AuthVersion `json:"expectedAuthVersion" binding:"required" swaggertype:"integer"`
	ExpectedAccessVersion int64                     `json:"expectedAccessVersion" binding:"required"`
	ExpectedRoleVersion   int64                     `json:"expectedRoleVersion" binding:"required"`
} // @name access_http.AdministratorRequest

func (h *Handler) changeAdministrator(w http.ResponseWriter, r *http.Request, grant bool) {
	actor, ok := principal(w, r)
	if !ok {
		return
	}
	var input AdministratorRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	version, err := h.service.ChangeAdministrator(r.Context(), service.AdministratorInput{
		Actor: actor, UserID: accountdomain.UserID(chi.URLParam(r, "id")), ExpectedAuthVersion: input.ExpectedAuthVersion,
		ExpectedAccessVersion: input.ExpectedAccessVersion, ExpectedRoleVersion: input.ExpectedRoleVersion, Grant: grant,
	})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, AssignmentResponse{AccessVersion: version})
}
