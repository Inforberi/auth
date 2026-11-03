package projects_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	mfaloginhttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/transport/http"
	mfamanagementhttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/management/transport/http"
	mfatelegramhttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/telegram/transport/http"
	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
	tokenhttp "github.com/Inforberi/financial-intelligence/internal/auth/token/transport/http"
)

func TestTwoProjectTelegramMFAHTTP(t *testing.T) {
	bot := &telegramHTTPBot{}
	f := prepareMFAHTTP(t, bot)
	f.trackTelegramLimits(t, "")
	ctx := t.Context()
	var users [2]string
	for i, web := range f.webs {
		owner := isolationAdminLogin(t, ctx, web, httpOwnerEmail)
		path := "/api/v1/admin/auth/settings/mfa/telegram/bot"
		response := web.call(t, ctx, "GET", path, "", owner, nil)
		require.Equal(t, 200, response.status, string(response.body))
		var saved settingshttp.TelegramBotResponse
		require.NoError(t, json.Unmarshal(response.body, &saved))
		token := fmt.Sprintf("%d:abcdefghijklmnopqrstuvwxyz_0123456789", 123456789+i)
		response = web.call(t, ctx, "POST", path, web.origin, owner, map[string]any{"expectedVersion": saved.Version, "botToken": token})
		require.Equal(t, 200, response.status, string(response.body))
		require.NotContains(t, string(response.body), token)
		require.NoError(t, json.Unmarshal(response.body, &saved))
		response = web.call(t, ctx, "POST", "/api/v1/admin/auth/settings/mfa/telegram/webhook", web.origin, owner, map[string]any{"expectedVersion": saved.Version})
		require.Equal(t, 200, response.status, string(response.body))
		require.NoError(t, json.Unmarshal(response.body, &saved))
		response = web.call(t, ctx, "POST", "/api/v1/admin/auth/settings/mfa/telegram", web.origin, owner, map[string]any{"expectedVersion": saved.Version, "allowed": true})
		require.Equal(t, 200, response.status, string(response.body))
		users[i] = isolationAdminLogin(t, ctx, web, httpIsolationEmail)
		response = web.call(t, ctx, "GET", path, "", users[i], nil)
		require.Equal(t, 403, response.status)
		response = web.call(t, ctx, "POST", "/api/v1/auth/mfa/telegram/preparation", web.origin, users[i], nil)
		require.Equal(t, 202, response.status, string(response.body))
		var prepared mfatelegramhttp.TelegramPreparationResponse
		require.NoError(t, json.Unmarshal(response.body, &prepared))
		f.trackTelegramLimits(t, prepared.Binding)
		require.True(t, strings.HasPrefix(prepared.URL, "https://t.me/Security"))
		update := map[string]any{"update_id": i + 1, "message": map[string]any{"message_id": i + 1, "date": time.Now().Unix(), "from": map[string]any{"id": 1099511627776, "is_bot": false}, "chat": map[string]any{"id": 1099511627776, "type": "private"}, "text": "/start " + prepared.Binding}}
		hookPath := "/api/v1/auth/mfa/telegram/webhook"
		secret := bot.secret(web.origin + hookPath)
		require.Len(t, secret, 43)
		response = web.call(t, ctx, "POST", hookPath, "", "", update, http.Header{"X-Telegram-Bot-Api-Secret-Token": {"wrong"}})
		require.Equal(t, 403, response.status)
		response = web.call(t, ctx, "POST", hookPath, "", "", update, http.Header{"X-Telegram-Bot-Api-Secret-Token": {secret}})
		require.Equal(t, 204, response.status, string(response.body))
		response = web.call(t, ctx, "POST", "/api/v1/auth/mfa/telegram/preparation/confirm", web.origin, users[i], map[string]string{"binding": prepared.Binding, "code": bot.latest()})
		require.Equal(t, 200, response.status, string(response.body))
		users[i] = response.cookie(t, "__Host-session")
		response = web.call(t, ctx, "POST", "/api/v1/auth/mfa/telegram", web.origin, users[i], nil)
		require.Equal(t, 200, response.status, string(response.body))
	}
	credentials := map[string]string{"email": httpIsolationEmail, "password": httpIsolationPassword}
	var challenges [2]mfaloginhttp.ChallengeResponse
	var cookies, codes [2]string
	for i, web := range f.webs {
		response := web.call(t, ctx, "POST", "/api/v1/auth/login/email", web.origin, "", credentials)
		require.Equal(t, 202, response.status, string(response.body))
		require.NoError(t, json.Unmarshal(response.body, &challenges[i]))
		f.trackCompletion(challenges[i].Challenge, strings.TrimPrefix(response.cookie(t, mfaloginhttp.LoginCookie), mfaloginhttp.LoginCookie+"="))
		require.Equal(t, "telegram", challenges[i].Method)
		cookies[i] = response.cookie(t, mfaloginhttp.LoginCookie)
		codes[i] = bot.latest()
	}
	foreign := f.webs[1].call(t, ctx, "POST", "/api/v1/auth/mfa/login/complete", f.webs[1].origin, cookies[0], map[string]string{"challenge": challenges[0].Challenge, "code": codes[0]})
	require.Equal(t, 400, foreign.status)
	for i, web := range f.webs {
		response := web.call(t, ctx, "POST", "/api/v1/auth/mfa/login/complete", web.origin, cookies[i], map[string]string{"challenge": challenges[i].Challenge, "code": codes[i]})
		require.Equal(t, 200, response.status, string(response.body))
		users[i] = response.cookie(t, "__Host-session")
		replay := web.call(t, ctx, "POST", "/api/v1/auth/mfa/login/complete", web.origin, cookies[i], map[string]string{"challenge": challenges[i].Challenge, "code": codes[i]})
		require.Equal(t, 400, replay.status)
	}
	web := f.webs[0]
	response := web.call(t, ctx, "GET", "/api/v1/auth/mfa/preference", "", users[0], nil)
	require.Equal(t, 200, response.status)
	var preference mfamanagementhttp.PreferenceResponse
	require.NoError(t, json.Unmarshal(response.body, &preference))
	reauth := web.call(t, ctx, "POST", "/api/v1/auth/reauthenticate/password", web.origin, users[0], map[string]string{"password": httpIsolationPassword})
	require.Equal(t, 200, reauth.status, string(reauth.body))
	users[0] = reauth.cookie(t, "__Host-session")
	response = web.call(t, ctx, "POST", "/api/v1/auth/mfa/preference", web.origin, users[0], map[string]any{"expectedVersion": preference.Version, "method": "telegram"})
	require.Equal(t, 200, response.status, string(response.body))
	require.NoError(t, f.projects.deps.Redis.Del(ctx, f.prefix[0]+f.mfa[0].Digest("telegram-login:resend:"+httpIsolationUser)).Err())
	bot.fail(true)
	response = web.call(t, ctx, "POST", "/api/v1/auth/login/email", web.origin, "", credentials)
	require.Equal(t, 503, response.status)
	response = web.call(t, ctx, "POST", "/api/v1/auth/mfa/recovery/login", web.origin, "", credentials)
	require.Equal(t, 202, response.status, string(response.body))
	bot.fail(false)
	require.NoError(t, f.projects.deps.Redis.Del(ctx, f.prefix[0]+f.mfa[0].Digest("telegram-login:resend:"+httpIsolationUser)).Err())
	response = web.call(t, ctx, "POST", "/api/v1/auth/native/password/login", "", "", map[string]any{"email": httpIsolationEmail, "password": httpIsolationPassword, "audience": "reports", "scope": []string{"reports.read"}})
	// Native policy in the shared fixture supplies its own declared audience.
	if response.status == 202 {
		var challenge tokenhttp.NativeChallengeResponse
		require.NoError(t, json.Unmarshal(response.body, &challenge))
		require.Equal(t, "telegram", challenge.Method)
		f.trackCompletion(challenge.Challenge, challenge.Binding)
		response = web.call(t, ctx, "POST", "/api/v1/auth/native/mfa/complete", "", "", map[string]any{"challenge": challenge.Challenge, "binding": challenge.Binding, "code": bot.latest()})
		require.Equal(t, 200, response.status, string(response.body))
	} else {
		require.FailNow(t, "native Telegram challenge", string(response.body))
	}
}
