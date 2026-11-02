package projects_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func (f projectProfileFixture) httpPasswordManagement(t *testing.T, ctx context.Context, origin, current string, request func(string, string, string, string) (int, []*http.Cookie)) string {
	t.Helper()
	const reauth = "/api/v1/auth/reauthenticate/password"
	const change = "/api/v1/auth/change-password"
	const replacement = "ReplacementHTTPPassword42!"
	cookieValue := func(cookies []*http.Cookie) string {
		t.Helper()
		for _, cookie := range cookies {
			if cookie.Name == "__Host-session" {
				require.True(t, cookie.Secure && cookie.HttpOnly)
				require.Empty(t, cookie.Domain)
				require.Equal(t, "/", cookie.Path)
				return cookie.Name + "=" + cookie.Value
			}
		}
		t.Fatal("missing session cookie")
		return ""
	}
	login := func(password string, expected int) string {
		t.Helper()
		code, cookies := request("/api/v1/auth/login/email", origin, "", `{"email":"runtime-email@example.test","password":"`+password+`"}`)
		require.Equal(t, expected, code)
		if expected != 200 {
			require.Empty(t, cookies)
			return ""
		}
		return cookieValue(cookies)
	}
	var originalHash string
	var verified pgtype.Timestamptz
	require.NoError(t, f.db.QueryRow(ctx, `SELECT p.password_hash,e.verified_at FROM auth.password_credentials p JOIN auth.user_emails e ON e.id=p.email_id WHERE p.user_id=$1`, f.sourceUser).Scan(&originalHash, &verified))
	require.True(t, verified.Valid)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, err := f.db.Exec(cleanup, `UPDATE auth.password_credentials SET password_hash=$2 WHERE user_id=$1`, f.sourceUser, originalHash)
		require.NoError(t, err)
		_, err = f.db.Exec(cleanup, `UPDATE auth.user_emails SET verified_at=$2 WHERE id=(SELECT email_id FROM auth.password_credentials WHERE user_id=$1)`, f.sourceUser, verified)
		require.NoError(t, err)
	})
	code, _ := request(change, origin, "", `!`)
	require.Equal(t, 401, code)
	code, _ = request(change, "", current, `!`)
	require.Equal(t, 403, code)
	code, _ = request(reauth, "https://foreign.example.test", current, `!`)
	require.Equal(t, 403, code)
	code, cookies := request(reauth, origin, current, `{"password":"wrong-password"}`)
	require.Equal(t, 401, code)
	require.Empty(t, cookies)
	var sessionID string
	var expires, absolute time.Time
	var mfaProof pgtype.Timestamptz
	hash := tokengenerate.New().Hash(strings.TrimPrefix(current, "__Host-session="))
	require.NoError(t, f.db.QueryRow(ctx, `SELECT id,expires_at,absolute_expires_at,mfa_verified_at FROM auth.sessions WHERE token_hash=$1`, hash).Scan(&sessionID, &expires, &absolute, &mfaProof))
	peer := login(f.password, 200)
	code, cookies = request(reauth, origin, current, `{"password":"`+f.password+`"}`)
	require.Equal(t, 200, code)
	rotated := cookieValue(cookies)
	require.NotEqual(t, current, rotated)
	code, _ = request("/api/v1/auth/token/exchange", origin, current, `!`)
	require.Equal(t, 401, code, "reauthentication consumes the old verifier")
	var newExpires, newAbsolute, passwordProof time.Time
	var newMFA pgtype.Timestamptz
	newHash := tokengenerate.New().Hash(strings.TrimPrefix(rotated, "__Host-session="))
	require.NoError(t, f.db.QueryRow(ctx, `SELECT expires_at,absolute_expires_at,password_verified_at,mfa_verified_at FROM auth.sessions WHERE id=$1 AND token_hash=$2`, sessionID, newHash).Scan(&newExpires, &newAbsolute, &passwordProof, &newMFA))
	require.Equal(t, expires, newExpires)
	require.Equal(t, absolute, newAbsolute)
	require.Equal(t, mfaProof, newMFA)
	require.False(t, passwordProof.IsZero())
	_, err := f.db.Exec(ctx, `UPDATE auth.user_emails SET verified_at=NULL WHERE id=(SELECT email_id FROM auth.password_credentials WHERE user_id=$1)`, f.sourceUser)
	require.NoError(t, err)
	payload := `{"oldPassword":"` + f.password + `","newPassword":"` + replacement + `","confirmPassword":"` + replacement + `"}`
	code, cookies = request(change, origin, rotated, payload)
	require.Equal(t, 403, code, "verified login contact remains required without configured SMTP")
	require.Empty(t, cookies)
	_, err = f.db.Exec(ctx, `UPDATE auth.user_emails SET verified_at=$2 WHERE id=(SELECT email_id FROM auth.password_credentials WHERE user_id=$1)`, f.sourceUser, verified)
	require.NoError(t, err)
	code, _ = request(change, origin, rotated, `{"oldPassword":"wrong-password","newPassword":"`+replacement+`","confirmPassword":"`+replacement+`"}`)
	require.Equal(t, 400, code)
	code, _ = request(change, origin, rotated, `{"oldPassword":"`+f.password+`","newPassword":"`+replacement+`","confirmPassword":"different"}`)
	require.Equal(t, 400, code)
	var version int64
	require.NoError(t, f.db.QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1`, f.sourceUser).Scan(&version))
	code, cookies = request(change, origin, rotated, payload)
	require.Equal(t, 200, code)
	require.Equal(t, "__Host-session=", cookieValue(cookies))
	var newVersion int64
	require.NoError(t, f.db.QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1`, f.sourceUser).Scan(&newVersion))
	require.Equal(t, version+1, newVersion)
	for _, cookie := range []string{rotated, peer} {
		code, _ = request("/api/v1/auth/token/exchange", origin, cookie, `!`)
		require.Equal(t, 401, code)
	}
	login(f.password, 400)
	newCookie := login(replacement, 200)
	code, cookies = request(change, origin, newCookie, `{"oldPassword":"`+replacement+`","newPassword":"`+f.password+`","confirmPassword":"`+f.password+`"}`)
	require.Equal(t, 200, code)
	require.Equal(t, "__Host-session=", cookieValue(cookies))
	return login(f.password, 200)
}
