package http

import (
	"net/http"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/administrators/service"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type Management struct {
	service *service.Management
	log     *zap.Logger
}

func NewManagement(service *service.Management, log *zap.Logger) *Management {
	return &Management{service: service, log: log}
}

type OperatorCommand struct {
	OperationID accountdomain.UserID `json:"operationId" swaggertype:"string"`
	UserID      accountdomain.UserID `json:"userId,omitempty" swaggertype:"string"`
	Action      string               `json:"action" enums:"invite,permissions,revoke"`
	Email       string               `json:"email,omitempty"`
	Permissions []domain.Permission  `json:"permissions" swaggertype:"array,string"`
} // @name operator_http.OperatorCommand

type OperatorReceipt struct {
	UserID accountdomain.UserID `json:"userId" swaggertype:"string"`
} // @name operator_http.OperatorReceipt

type OperatorPage struct {
	Items      []domain.Operator    `json:"items"`
	NextCursor accountdomain.UserID `json:"nextCursor,omitempty" swaggertype:"string"`
} // @name operator_http.OperatorPage

// @Summary List platform operators
// @Tags Platform Operators
// @Param after query string false "Cursor from the previous page"
// @Success 200 {object} OperatorPage
// @Security SessionCookie
// @ID getPlatformOperators
// @Router /api/v1/platform/operators [get]
func (h *Management) List(w http.ResponseWriter, r *http.Request) {
	actor, ok := projecthttp.RequestActor(w, r)
	if !ok {
		return
	}
	items, err := h.service.List(r.Context(), actor, accountdomain.UserID(r.URL.Query().Get("after")))
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	page := OperatorPage{Items: items}
	if len(items) == 50 {
		page.NextCursor = items[len(items)-1].UserID
	}
	httpx.JSON(w, 200, page)
}

// @Summary Invite an operator, replace project permissions or revoke access
// @Tags Platform Operators
// @Param body body OperatorCommand true "Owner-only command"
// @Success 200 {object} OperatorReceipt
// @Security SessionCookie
// @ID postPlatformOperators
// @Router /api/v1/platform/operators [post]
func (h *Management) Apply(w http.ResponseWriter, r *http.Request) {
	actor, ok := projecthttp.RequestActor(w, r)
	if !ok {
		return
	}
	var command OperatorCommand
	if err := httpx.DecodeJSON(w, r, &command); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	user, err := h.service.Apply(r.Context(), actor, domain.Management{OperationID: command.OperationID, UserID: command.UserID, Action: command.Action, Email: command.Email, Permissions: command.Permissions})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, OperatorReceipt{UserID: user})
}

var managementErrors = append(projecthttp.CatalogErrorRules(),
	httpx.MatchError(domain.ErrInvalidManagement, 400, "invalid_command", "invalid operator command"),
	httpx.MatchError(domain.ErrOperatorConflict, 409, "operator_conflict", "operator command conflict"),
	httpx.MatchError(domain.ErrOwnerProtected, 409, "owner_protected", "platform owner cannot be changed"),
	httpx.MatchError(accountdomain.ErrProvisionConflict, 409, "operator_conflict", "operator command conflict"),
	httpx.MatchError(accountdomain.ErrProvisionEmailExists, 409, "email_unavailable", "email unavailable"),
	httpx.MatchError(accountdomain.ErrEmailInvalid, 400, "invalid_email", "invalid email"),
	httpx.MatchError(accountdomain.ErrEmailRequired, 400, "invalid_email", "invalid email"),
	httpx.MatchError(accountdomain.ErrProvisionDisabled, 404, "method_disabled", "operator invitations disabled"),
	httpx.ErrorRule{Target: accountdomain.ErrVerificationLimited, Response: httpx.Failure{Status: 429, Code: "rate_limited", Message: "rate limited", Headers: http.Header{"Retry-After": {"60"}}}},
)

func (h *Management) respondError(w http.ResponseWriter, r *http.Request, err error) {
	httpx.RespondError(w, r, h.log, "platform_operator_management", err, managementErrors, httpx.Failure{Status: 503, Code: "temporarily_unavailable", Message: "temporarily unavailable"})
}
