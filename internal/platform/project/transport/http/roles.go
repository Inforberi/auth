package http

import (
	"context"
	"io"
	"net/http"

	"go.uber.org/zap"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type roleService interface {
	CreateRole(context.Context, operatordomain.Principal, domain.RoleCreation) (domain.RoleCreationResult, error)
	ReadRoleOutcome(context.Context, operatordomain.Principal, domain.ID, domain.ID) (domain.RoleCreationOutcome, error)
	ReconcileRoleOutcome(context.Context, operatordomain.Principal, domain.ID, domain.ID) (domain.RoleCreationOutcome, error)
}

type RoleHandler struct {
	service roleService
	log     *zap.Logger
}

func NewRoles(service roleService, log *zap.Logger) *RoleHandler {
	return &RoleHandler{service: service, log: log}
}

type PlatformRoleResponse struct {
	ID          accessdomain.RoleID          `json:"id" swaggertype:"string"`
	Key         string                       `json:"key"`
	Name        string                       `json:"name"`
	Description string                       `json:"description"`
	Permissions []accessdomain.PermissionKey `json:"permissions" swaggertype:"array,string"`
	MFARequired bool                         `json:"mfaRequired"`
	Version     int64                        `json:"version"`
} // @name project_http.PlatformRoleResponse

type RoleOutcomeResponse struct {
	OperationID domain.ID             `json:"operationId" swaggertype:"string"`
	ProjectID   domain.ID             `json:"projectId" swaggertype:"string"`
	Committed   bool                  `json:"committed"`
	Role        *PlatformRoleResponse `json:"role,omitempty"`
} // @name project_http.RoleOutcomeResponse

func platformRoleResponse(role accessdomain.Role) *PlatformRoleResponse {
	permissions := role.Permissions
	if permissions == nil {
		permissions = []accessdomain.PermissionKey{}
	}
	return &PlatformRoleResponse{
		ID: role.ID, Key: role.Key, Name: role.Name, Description: role.Description,
		Permissions: permissions, MFARequired: role.MFARequired, Version: role.Version,
	}
}

func roleOutcomeResponse(result domain.RoleCreationOutcome) RoleOutcomeResponse {
	response := RoleOutcomeResponse{OperationID: result.OperationID, ProjectID: result.ProjectID, Committed: result.Committed}
	if result.Committed {
		response.Role = platformRoleResponse(result.Role)
	}
	return response
}

func roleActor(w http.ResponseWriter, r *http.Request) (operatordomain.Principal, bool) {
	actor, ok := requestActor(w, r)
	if !ok {
		return actor, false
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		httpx.Error(w, 400, "invalid_query", "query parameters are not supported")
		return actor, false
	}
	return actor, true
}

func emptyRoleBody(w http.ResponseWriter, r *http.Request) bool {
	if r.Body == nil {
		return true
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 1))
	if err != nil || len(data) != 0 {
		httpx.Error(w, 400, "invalid_body", "request body must be empty")
		return false
	}
	return true
}

var roleErrors = append([]httpx.ErrorRule{
	httpx.MatchError(accessdomain.ErrInvalidRole, 400, "invalid_role", "invalid role"),
	httpx.MatchError(accessdomain.ErrInvalidPermission, 400, "invalid_permission", "invalid permission"),
	httpx.MatchError(accessdomain.ErrMFANotReady, 409, "mfa_not_ready", "project MFA capability is not available"),
	httpx.MatchError(accessdomain.ErrConflict, 409, "role_conflict", "role key already exists"),
	httpx.MatchError(domain.ErrNotFound, 404, "role_operation_not_found", "role operation not found"),
	httpx.MatchError(domain.ErrAdmissionExpired, 503, "temporarily_unavailable", "temporarily unavailable"),
}, catalogErrors...)

func (h *RoleHandler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	httpx.RespondError(w, r, h.log, "platform_roles", err, roleErrors,
		httpx.Failure{Status: 503, Code: "temporarily_unavailable", Message: "temporarily unavailable"})
}
