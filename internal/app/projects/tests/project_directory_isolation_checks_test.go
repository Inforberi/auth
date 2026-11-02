package projects_test

import (
	"context"
	"net/url"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func checkProjectDirectoryIsolation(t *testing.T, ctx context.Context, f projectIsolationHTTP, webs [2]isolationHTTP) {
	t.Helper()
	const path = "/api/v1/admin/users"
	owners := [2]string{isolationAdminLogin(t, ctx, webs[0], httpOwnerEmail), isolationAdminLogin(t, ctx, webs[1], httpOwnerEmail)}
	var cards [2]accounthttp.UserDetailResponse
	var directoryRoles [2]accounthttp.UserRoleResponse
	for i, web := range webs {
		isolationCommand(t, ctx, web, "GET", path, owners[1-i], nil, 401, nil)
		isolationCommand(t, ctx, web, "GET", path+"/"+httpIsolationUser, owners[1-i], nil, 401, nil)
		isolationCommand(t, ctx, web, "GET", path+"/"+directoryExclusiveIDs[1-i], owners[i], nil, 404, nil)
		isolationCommand(t, ctx, web, "GET", path+"/"+httpIsolationUser, owners[i], nil, 200, &cards[i])
		require.Equal(t, accountdomain.UserID(httpIsolationUser), cards[i].ID)
		require.True(t, cards[i].PasswordConfigured)
		require.Len(t, cards[i].Contacts, 1)
		require.Equal(t, httpIsolationEmail, cards[i].Contacts[0].Email)
		require.Len(t, cards[i].Roles, 2)
		for _, role := range cards[i].Roles {
			if role.Key == "directory_reader" {
				directoryRoles[i] = role
			}
		}
		require.NotEmpty(t, directoryRoles[i].ID)
		require.Equal(t, "Directory "+strconv.Itoa(i), directoryRoles[i].Name)
		var filtered accounthttp.UserPageResponse
		isolationCommand(t, ctx, web, "GET", path+"?email="+url.QueryEscape("directory-"+strconv.Itoa(1-i)+"@example.test"), owners[i], nil, 200, &filtered)
		require.Empty(t, filtered.Users)
		seen := map[accountdomain.UserID]bool{}
		cursor := ""
		for page := 0; page < 3; page++ {
			var listed accounthttp.UserPageResponse
			isolationCommand(t, ctx, web, "GET", path+"?limit=2&before="+url.QueryEscape(cursor), owners[i], nil, 200, &listed)
			require.LessOrEqual(t, len(listed.Users), 2)
			for _, user := range listed.Users {
				require.False(t, seen[user.ID], "cursor must not repeat rows")
				require.NotEqual(t, accountdomain.UserID(directoryExclusiveIDs[1-i]), user.ID)
				seen[user.ID] = true
			}
			cursor = listed.NextCursor
			if cursor == "" {
				break
			}
		}
		require.Empty(t, cursor)
		require.Len(t, seen, 4)
		for _, id := range []string{httpIsolationUser, httpOwnerID, httpManagerID, directoryExclusiveIDs[i]} {
			require.True(t, seen[accountdomain.UserID(id)])
		}
		isolationCommand(t, ctx, web, "GET", path+"?email="+url.QueryEscape(httpIsolationEmail), owners[i], nil, 200, &filtered)
		require.Len(t, filtered.Users, 1)
		require.Equal(t, cards[i].Status, filtered.Users[0].Status)
	}
	require.Equal(t, accountdomain.StatusActive, cards[0].Status)
	require.Equal(t, accountdomain.StatusBlocked, cards[1].Status)
	require.EqualValues(t, 1, cards[0].AuthVersion)
	require.EqualValues(t, 7, cards[1].AuthVersion)
	require.Equal(t, []string{"https://accounts.google.com"}, cards[0].ExternalIssuers)
	require.Equal(t, []string{"https://oauth.telegram.org"}, cards[1].ExternalIssuers)
	require.NotEqual(t, directoryRoles[0].ID, directoryRoles[1].ID)
	ordinary := isolationSessionLogin(t, ctx, webs[0])
	isolationCommand(t, ctx, webs[0], "GET", path, ordinary, nil, 403, nil)
	isolationCommand(t, ctx, webs[0], "GET", path+"/"+httpIsolationUser, ordinary, nil, 403, nil)
	// Directory reads need current permission, not a fresh password confirmation.
	_, err := f.databases[0].Exec(ctx, `UPDATE auth.sessions SET password_verified_at=clock_timestamp()-interval '10 minutes' WHERE token_hash=$1`, tokengenerate.New().Hash(isolationRawCookie(owners[0])))
	require.NoError(t, err)
	isolationCommand(t, ctx, webs[0], "GET", path, owners[0], nil, 200, nil)
	var managers [2]string
	for i, web := range webs {
		response := web.call(t, ctx, "POST", "/api/v1/auth/login/email", web.origin, "", map[string]string{"email": httpManagerEmail, "password": httpIsolationPassword})
		require.Equal(t, 200, response.status, "%s", response.body)
		managers[i] = response.cookie(t, "__Host-session")
	}
	_, err = f.databases[0].Exec(ctx, `DELETE FROM auth.role_permissions WHERE permission_key='accounts.users.read' AND role_id IN(SELECT id FROM auth.roles WHERE key='http_admin_manager')`)
	require.NoError(t, err)
	isolationCommand(t, ctx, webs[0], "GET", path, managers[0], nil, 403, nil)
	isolationCommand(t, ctx, webs[1], "GET", path, managers[1], nil, 200, nil)
}
