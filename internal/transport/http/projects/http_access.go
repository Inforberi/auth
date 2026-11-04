package browser

import (
	"net/http"

	"go.uber.org/zap"

	accesshttp "github.com/Inforberi/financial-intelligence/internal/access/transport/http"
)

func (p *binding) accessHandlers(handlers map[string]http.HandlerFunc, log *zap.Logger) {
	if p.Access == nil {
		return
	}
	h := accesshttp.New(p.Access, log)
	handlers["GET /api/v1/auth/access"] = h.MyAccess
	handlers["GET /api/v1/admin/permissions"] = h.PermissionCatalog
	handlers["GET /api/v1/admin/roles"], handlers["GET /api/v1/admin/roles/{id}"] = h.ListRoles, h.ReadRole
	handlers["GET /api/v1/admin/users/{id}/access"] = h.UserAssignments
	handlers["POST /api/v1/admin/roles"], handlers["POST /api/v1/admin/roles/{id}"] = h.CreateRole, h.UpdateRole
	handlers["POST /api/v1/admin/users/{id}/roles/{roleId}"], handlers["DELETE /api/v1/admin/users/{id}/roles/{roleId}"] = h.GrantRole, h.RevokeRole
	handlers["POST /api/v1/admin/users/{id}/administrator"], handlers["DELETE /api/v1/admin/users/{id}/administrator"] = h.GrantAdministrator, h.RevokeAdministrator
}
