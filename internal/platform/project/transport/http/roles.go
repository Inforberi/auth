package http

import (
	"context"
	"io"
	"net/http"

	"go.uber.org/zap"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type roleService interface {
	ListProjectRoles(context.Context, operatordomain.Principal, service.ProjectRoleQuery) (service.ProjectRolePage, error)
	ReadProjectRole(context.Context, operatordomain.Principal, domain.DirectoryTarget, accessdomain.RoleID) (accessdomain.Role, error)
	ChangeRoleAssignment(context.Context, operatordomain.Principal, domain.RoleAssignment) (domain.RoleAssignmentResult, error)
	CreateRole(context.Context, operatordomain.Principal, domain.RoleCreation) (domain.RoleCreationResult, error)
	ReadRoleOutcome(context.Context, operatordomain.Principal, domain.ID, domain.ID) (domain.RoleOutcome, error)
	ReconcileRoleOutcome(context.Context, operatordomain.Principal, domain.ID, domain.ID) (domain.RoleOutcome, error)
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
	System      bool                         `json:"system"`
	Version     int64                        `json:"version"`
} // @name project_http.PlatformRoleResponse

type RoleOutcomeResponse struct {
	OperationID   domain.ID             `json:"operationId" swaggertype:"string"`
	ProjectID     domain.ID             `json:"projectId" swaggertype:"string"`
	Action        domain.RoleAction     `json:"action" swaggertype:"string"`
	UserID        accountdomain.UserID  `json:"userId,omitempty" swaggertype:"string"`
	AccessVersion int64                 `json:"accessVersion,omitempty"`
	Changed       *bool                 `json:"changed,omitempty"`
	Committed     bool                  `json:"committed"`
	Role          *PlatformRoleResponse `json:"role,omitempty"`
} // @name project_http.RoleOutcomeResponse

func platformRoleResponse(role accessdomain.Role) *PlatformRoleResponse {
	permissions := role.Permissions
	if permissions == nil {
		permissions = []accessdomain.PermissionKey{}
	}
	return &PlatformRoleResponse{
		ID: role.ID, Key: role.Key, Name: role.Name, Description: role.Description,
		Permissions: permissions, MFARequired: role.MFARequired, System: role.System, Version: role.Version,
	}
}

func roleOutcomeResponse(result domain.RoleOutcome) RoleOutcomeResponse {
	response := RoleOutcomeResponse{OperationID: result.OperationID, ProjectID: result.ProjectID, Action: result.Action, Committed: result.Committed}
	if result.Committed {
		response.Role = platformRoleResponse(result.Role)
		if result.Action == domain.RoleGrant || result.Action == domain.RoleRevoke {
			response.UserID, response.AccessVersion, response.Changed = result.UserID, result.AccessVersion, &result.Changed
		}
	}
	return response
}

func roleOperationLocation(project, operation domain.ID) string {
	return "/api/v1/platform/projects/" + string(project) + "/role-operations/" + string(operation)
}

func operationActor(w http.ResponseWriter, r *http.Request) (operatordomain.Principal, bool) {
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

func emptyRequestBody(w http.ResponseWriter, r *http.Request) bool {
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
	httpx.MatchError(accessdomain.ErrForbidden, 403, "forbidden", "system role assignments require a separate administrator flow"),
	httpx.MatchError(accessdomain.ErrRoleNotFound, 404, "role_not_found", "role not found"),
	httpx.MatchError(accessdomain.ErrTargetUnavailable, 409, "target_unavailable", "target user is unavailable"),
	httpx.MatchError(accessdomain.ErrInvalidRole, 400, "invalid_role", "invalid role"),
	httpx.MatchError(accessdomain.ErrInvalidPermission, 400, "invalid_permission", "invalid permission"),
	httpx.MatchError(accessdomain.ErrMFANotReady, 409, "mfa_not_ready", "project MFA capability is not available"),
	httpx.MatchError(accessdomain.ErrConflict, 409, "role_conflict", "role or access changed; reload and retry"),
	httpx.MatchError(domain.ErrNotFound, 404, "role_operation_not_found", "role operation not found"),
	httpx.MatchError(domain.ErrAdmissionExpired, 503, "temporarily_unavailable", "temporarily unavailable"),
}, catalogErrors...)

func (h *RoleHandler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	httpx.RespondError(w, r, h.log, "platform_roles", err, roleErrors,
		httpx.Failure{Status: 503, Code: "temporarily_unavailable", Message: "temporarily unavailable"})
}
