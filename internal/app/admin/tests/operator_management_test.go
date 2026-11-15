package admin_test

import (
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
)

func operatorManagementDrill(t *testing.T, db *pgxpool.Pool, h *operatorHTTPS, owner operatordomain.Principal, session *http.Cookie) {
	t.Helper()
	ctx := t.Context()
	const path = "/api/v1/platform/operators"
	cookies := []*http.Cookie{session}
	invite := map[string]any{
		"action": "invite", "operationId": "41000000-0000-4000-8000-000000000001",
		"email": "delegate@example.test", "permissions": []string{"platform.projects.read"},
	}
	h.call("POST", path, invite, nil, 401)
	first, _ := h.call("POST", path, invite, cookies, 200)
	user := operatorField(t, first, "userId")
	replay, _ := h.call("POST", path, invite, cookies, 200)
	require.Equal(t, user, operatorField(t, replay, "userId"))
	var jobs int
	require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.invitation_outbox o JOIN auth.account_invitations i USING(digest) WHERE i.user_id=$1`, user).Scan(&jobs))
	require.Equal(t, 1, jobs)
	var allowed bool
	require.NoError(t, db.QueryRow(ctx, `SELECT auth.has_administrative_access($1)`, user).Scan(&allowed))
	require.True(t, allowed)

	update := map[string]any{"action": "permissions", "userId": user,
		"operationId": "41000000-0000-4000-8000-000000000002", "permissions": []string{"platform.operators.manage"}}
	h.call("POST", path, update, cookies, 400)
	update["permissions"] = []string{"platform.projects.read", "platform.project_users.manage"}
	h.call("POST", path, update, cookies, 200)
	h.call("GET", path, nil, cookies, 200)

	revoke := map[string]any{"action": "revoke", "userId": owner.UserID, "operationId": "41000000-0000-4000-8000-000000000003"}
	h.call("POST", path, revoke, cookies, 409)
	revoke["userId"] = user
	h.call("POST", path, revoke, cookies, 200)
	h.call("POST", path, revoke, cookies, 200)
	require.NoError(t, db.QueryRow(ctx, `SELECT auth.has_administrative_access($1)
		OR EXISTS(SELECT 1 FROM auth.account_invitations WHERE user_id=$1)`, user).Scan(&allowed))
	require.False(t, allowed)
}
