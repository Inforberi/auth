package projects_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	projectprofile "github.com/Inforberi/financial-intelligence/internal/app/projects/profile"
)

var directoryExclusiveIDs = [2]string{"f8a00000-0000-4000-8000-000000000001", "f8a00000-0000-4000-8000-000000000002"}

func TestTwoProjectDirectoryIsolationSQL(t *testing.T) {
	pair := prepareHTTPProjects(t)
	f := newProjectIsolationHTTP(t, pair.admin, pair.reader, pair.a, pair.b, pair.target)
	ctx := t.Context()
	for i, db := range f.databases {
		seedHTTPAdministrators(t, ctx, db)
		_, err := db.Exec(ctx, `INSERT INTO auth.users(id) VALUES($1)`, directoryExclusiveIDs[i])
		require.NoError(t, err)
		_, err = db.Exec(ctx, `INSERT INTO auth.user_emails(user_id,email) VALUES($1,$2)`, directoryExclusiveIDs[i], fmt.Sprintf("directory-%d@example.test", i))
		require.NoError(t, err)
		_, err = db.Exec(ctx, `INSERT INTO auth.roles(key,name) VALUES('directory_reader',$1)`, fmt.Sprintf("Directory %d", i))
		require.NoError(t, err)
		_, err = db.Exec(ctx, `INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM auth.roles WHERE key='directory_reader'`, httpIsolationUser)
		require.NoError(t, err)
		issuer := "https://accounts.google.com"
		if i == 1 {
			issuer = "https://oauth.telegram.org"
		}
		_, err = db.Exec(ctx, `INSERT INTO auth.linked_identities(user_id,issuer,subject) VALUES($1,$2,'directory-only-subject')`, httpIsolationUser, issuer)
		require.NoError(t, err)
		f.redisKeys[f.passwordPrefix[i]+f.passwordCipher[i].Digest("reauth-user:"+httpOwnerID)] = struct{}{}
	}
	_, err := f.databases[1].Exec(ctx, `UPDATE auth.users SET status='blocked',auth_version=7 WHERE id=$1`, httpIsolationUser)
	require.NoError(t, err)
	f.trackLogin(httpOwnerEmail)
	f.trackLogin(httpManagerEmail)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		for i, db := range f.databases {
			_, err := db.Exec(cleanup, `DELETE FROM auth.user_roles WHERE role_id IN(SELECT id FROM auth.roles WHERE key='directory_reader'); DELETE FROM auth.roles WHERE key='directory_reader'`)
			require.NoError(t, err)
			_, err = db.Exec(cleanup, `DELETE FROM auth.users WHERE id=$1`, directoryExclusiveIDs[i])
			require.NoError(t, err)
		}
	})
	webs, _, _ := f.serve(t, projectprofile.ProjectProfileConfig{BrowserEnabled: true, Password: &f.password, UserDirectoryEnabled: true, Timeout: 5 * time.Second})
	checkProjectDirectoryIsolation(t, ctx, f, webs)
}
