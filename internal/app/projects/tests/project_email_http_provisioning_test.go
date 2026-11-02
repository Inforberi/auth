package projects_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
	passwordhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
)

func checkEmailHTTPProvisioning(t *testing.T, ctx context.Context, f *emailIsolationFixture, webs [2]isolationHTTP, owners [2]string) {
	t.Helper()
	var invitations [2]string
	var invited [2]accountservice.ProvisionResult
	input := accounthttp.ProvisionRequest{IdempotencyKey: "e8b00000-0000-4000-8000-000000000001", Email: "isolation-invite@example.test", Invite: true}
	for i, web := range webs {
		isolationCommand(t, ctx, web, "POST", "/api/v1/admin/users", owners[1-i], input, 401, nil)
		isolationCommand(t, ctx, web, "POST", "/api/v1/admin/users", "", input, 401, nil)
		response := web.call(t, ctx, "POST", "/api/v1/admin/users", "https://foreign.example.test", owners[i], input)
		require.Equal(t, 403, response.status)
		isolationCommand(t, ctx, web, "POST", "/api/v1/admin/users", owners[i], input, 201, &invited[i])
		f.users[i] = append(f.users[i], string(invited[i].UserID))
		var replay accountservice.ProvisionResult
		isolationCommand(t, ctx, web, "POST", "/api/v1/admin/users", owners[i], input, 200, &replay)
		require.True(t, replay.Reused)
		require.Equal(t, invited[i].UserID, replay.UserID)
		payload := isolationEmailPayload(t, ctx, f.projects.databases[i], `SELECT o.payload FROM auth.invitation_outbox o JOIN auth.account_invitations v USING(digest) WHERE v.user_id=$1`, invited[i].UserID)
		invitations[i] = isolationEmailToken(t, f.ciphers[i][0], payload, f.configs[i].Invitations.URL, input.Email)
	}
	require.NotEqual(t, invited[0].UserID, invited[1].UserID)
	for i, web := range webs {
		isolationCommand(t, ctx, web, "GET", "/api/v1/auth/invitations/activate?token="+invitations[i], "", nil, 405, nil)
		isolationCommand(t, ctx, web, "POST", "/api/v1/auth/invitations/activate", "", passwordhttp.ActivationRequest{Token: invitations[1-i], Password: httpIsolationPassword, ConfirmPassword: httpIsolationPassword}, 400, nil)
	}
	for i, web := range webs {
		activation := passwordhttp.ActivationRequest{Token: invitations[i], Password: httpIsolationPassword, ConfirmPassword: httpIsolationPassword}
		response := web.call(t, ctx, "POST", "/api/v1/auth/invitations/activate", web.origin, "", activation)
		require.Equal(t, 200, response.status, "%s", response.body)
		requireNoEmailLoginCookie(t, response)
		isolationCommand(t, ctx, web, "POST", "/api/v1/auth/invitations/activate", "", activation, 400, nil)
	}
	var temporary [2]passwordhttp.TemporaryIssueResponse
	var setup [2]passwordhttp.TemporaryLoginResponse
	request := passwordhttp.TemporaryProvisionRequest{IdempotencyKey: "e8b00000-0000-4000-8000-000000000002", Email: "isolation-temp@example.test"}
	for i, web := range webs {
		isolationCommand(t, ctx, web, "POST", "/api/v1/admin/users/temporary-password", owners[1-i], request, 401, nil)
		isolationCommand(t, ctx, web, "POST", "/api/v1/admin/users/temporary-password", owners[i], request, 201, &temporary[i])
		f.users[i] = append(f.users[i], string(temporary[i].UserID))
		require.NotEmpty(t, temporary[i].Password)
		var replay passwordhttp.TemporaryIssueResponse
		isolationCommand(t, ctx, web, "POST", "/api/v1/admin/users/temporary-password", owners[i], request, 200, &replay)
		require.True(t, replay.Reused)
		require.Empty(t, replay.Password)
	}
	for i, web := range webs {
		isolationCommand(t, ctx, web, "POST", "/api/v1/auth/temporary-password/login", "", passwordhttp.TemporaryLoginRequest{Email: request.Email, Password: temporary[1-i].Password}, 400, nil)
		response := web.call(t, ctx, "POST", "/api/v1/auth/temporary-password/login", web.origin, "", passwordhttp.TemporaryLoginRequest{Email: request.Email, Password: temporary[i].Password})
		require.Equal(t, 200, response.status, "%s", response.body)
		requireNoEmailLoginCookie(t, response)
		require.NoError(t, json.Unmarshal(response.body, &setup[i]))
		require.Equal(t, "password_change_required", setup[i].Status)
	}
	for i, web := range webs {
		isolationCommand(t, ctx, web, "POST", "/api/v1/auth/temporary-password/complete", "", passwordhttp.TemporaryCompleteRequest{Token: setup[1-i].Token, Password: httpIsolationPassword, ConfirmPassword: httpIsolationPassword}, 400, nil)
	}
	for i, web := range webs {
		complete := passwordhttp.TemporaryCompleteRequest{Token: setup[i].Token, Password: httpIsolationPassword, ConfirmPassword: httpIsolationPassword}
		response := web.call(t, ctx, "POST", "/api/v1/auth/temporary-password/complete", web.origin, "", complete)
		require.Equal(t, 200, response.status, "%s", response.body)
		requireNoEmailLoginCookie(t, response)
		isolationCommand(t, ctx, web, "POST", "/api/v1/auth/temporary-password/complete", "", complete, 400, nil)
	}
}
