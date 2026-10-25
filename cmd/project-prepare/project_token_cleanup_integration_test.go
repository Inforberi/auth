package main

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

func (f projectTokenFixture) cleanupTokenLimits(t *testing.T, ctx context.Context, scope realmscope.Scope, ciphers map[string]*secretbox.Cipher, keys *[]string) {
	t.Helper()
	jwtPrefix, err := scope.RedisPrefix("jwt-issuance", "auth:{jwt-issuance}:")
	require.NoError(t, err)
	lookup, err := scope.RedisPrefix("jwt-refresh-lookup", "auth:{jwt-refresh-lookup}:")
	require.NoError(t, err)
	password, err := scope.RedisPrefix("password-limit", "auth:password-recovery:limit:")
	require.NoError(t, err)
	mfa, err := scope.RedisPrefix("mfa-limit", "auth:mfa:limit:")
	require.NoError(t, err)
	jwt := ciphers["jwt-issuance-limits:v1"]
	pwd := ciphers["password-reset:v1"]
	email := ciphers["email-login:v1"]
	factor := ciphers["mfa:v1"]
	*keys = append(*keys, jwtPrefix+"project", jwtPrefix+"ip:"+jwt.Digest(tokenFixtureIP), lookup+"project", lookup+"ip:"+jwt.Digest(tokenFixtureIP), password+pwd.Digest("login-ip:"+tokenFixtureIP), password+pwd.Digest("login-global"), mfa+"project", mfa+"login:ip:"+factor.Digest(tokenFixtureIP))
	for i, user := range tokenFixtureUsers {
		*keys = append(*keys, jwtPrefix+"actor:"+jwt.Digest(user), password+pwd.Digest("login-email:"+tokenFixtureEmails[i]), mfa+factor.Digest("user:"+user), mfa+factor.Digest("login:factor-user:"+user))
	}
	for _, logical := range []string{"request:ip:" + tokenFixtureIP, "request:project", "request:email:" + tokenFixtureEmails[2], "request:cooldown:" + tokenFixtureEmails[2], "confirm:ip:" + tokenFixtureIP, "confirm:project"} {
		*keys = append(*keys, password+email.Digest(logical))
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		rows, err := f.db.Query(cleanup, `SELECT id FROM auth.sessions WHERE user_id=ANY($1::uuid[])`, tokenFixtureUsers)
		require.NoError(t, err)
		for rows.Next() {
			var id string
			require.NoError(t, rows.Scan(&id))
			*keys = append(*keys, jwtPrefix+"session:"+jwt.Digest(id))
		}
		require.NoError(t, rows.Err())
		rows.Close()
		require.NoError(t, f.rdb.Del(cleanup, (*keys)...).Err())
	})
}
