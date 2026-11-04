package projects_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	appauth "github.com/Inforberi/financial-intelligence/internal/app/auth"
	accountemail "github.com/Inforberi/financial-intelligence/internal/auth/account/email/service"
	accountprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/service"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	passwordrecovery "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/recovery/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingssmtp "github.com/Inforberi/financial-intelligence/internal/auth/settings/smtp/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

const emailIsolationIP = "192.0.2.89"

type emailIsolationFixture struct {
	projects  projectIsolationHTTP
	services  [2]*appauth.ProjectEmail
	ciphers   [2][2]*secretbox.Cipher
	listeners [2]net.Listener
	configs   [2]appauth.ProjectEmailConfig
	users     [2][]string
}

func TestTwoProjectEmailIsolationSQL(t *testing.T) {
	pair := prepareHTTPProjects(t)
	f := newProjectIsolationHTTP(t, pair.admin, pair.reader, pair.a, pair.b, pair.target)
	email := prepareEmailIsolation(t, f)
	checkEmailVerificationResetIsolation(t, t.Context(), email)
	checkInvitationTemporaryIsolation(t, t.Context(), email)
	checkEmailChangeIsolation(t, t.Context(), email)
}

func prepareEmailIsolation(t *testing.T, projects projectIsolationHTTP) *emailIsolationFixture {
	t.Helper()
	ctx := t.Context()
	f := &emailIsolationFixture{projects: projects}
	deps := appauth.ProjectSMTPDependencies{Registry: projects.deps.Registry, Reader: projects.deps.Reader, Redis: projects.deps.Redis}
	for i, key := range projects.projects {
		db := projects.databases[i]
		seedHTTPAdministrators(t, ctx, db)
		_, err := db.Exec(ctx, `CREATE TEMP TABLE isolation_smtp_before AS TABLE auth.smtp_settings;
 DELETE FROM auth.smtp_settings;
 UPDATE auth.auth_settings SET password_email_verification='optional';
 INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,'accounts.users.manage' FROM auth.roles WHERE key='super_admin'`)
		require.NoError(t, err)
		_, err = db.Exec(ctx, `UPDATE auth.user_emails SET verified_at=NULL WHERE user_id=$1`, httpIsolationUser)
		require.NoError(t, err)
		configuration, err := deps.Reader.LoadAuthConfiguration(ctx, key, deps.Registry)
		require.NoError(t, err)
		scope, err := realmscope.New("project", string(key.Binding.ProjectID))
		require.NoError(t, err)
		ciphers := make([]*secretbox.Cipher, 3)
		for j, name := range []string{"email-verification:v1", "password-reset:v1", "smtp-settings:v1"} {
			purpose, err := scope.Purpose(name)
			require.NoError(t, err)
			ciphers[j], err = secretbox.NewScoped(configuration.EncryptionKey(), purpose)
			require.NoError(t, err)
		}
		f.ciphers[i] = [2]*secretbox.Cipher{ciphers[0], ciphers[1]}
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		f.listeners[i] = listener
		t.Cleanup(func() { require.NoError(t, listener.Close()) })
		host, portString, err := net.SplitHostPort(listener.Addr().String())
		require.NoError(t, err)
		port, err := strconv.Atoi(portString)
		require.NoError(t, err)
		allowed := []string{listener.Addr().String()}
		smtp := settingsdomain.SMTPConfig{Host: host, Port: port, Username: fmt.Sprintf("project-%d", i), From: fmt.Sprintf("auth-%d@example.test", i), Domain: "example.test", RequireTLS: true}
		seed, err := settingssmtp.NewSMTPSeed(smtp, fmt.Sprintf("smtp-project-%d-fixture-only", i), allowed, true, ciphers[2])
		require.NoError(t, err)
		encoded, err := json.Marshal(smtp)
		require.NoError(t, err)
		_, err = db.Exec(ctx, `INSERT INTO auth.smtp_settings(singleton,configuration,password_set,password) VALUES(true,$1::jsonb,true,$2)`, string(encoded), seed.Password)
		require.NoError(t, err)
		origin := projects.origins[i]
		cfg := appauth.ProjectEmailConfig{
			VerificationEnabled: true, RecoveryEnabled: true, Origin: origin,
			Verification: accountservice.Config{URL: origin + "/verify-email", TTL: 30 * time.Minute, ResendInterval: time.Minute, RegistrationIPLimit: 10, RegistrationGlobalLimit: 100},
			Password:     passwordrecovery.Config{ResetURL: origin + "/reset-password", ResetTokenTTL: time.Hour, ResetGlobalLimit: 100},
			Invitations:  accountprovisioning.InvitationConfig{Enabled: true, URL: origin + "/activate", TTL: time.Hour, ActivationGlobalLimit: 100, ReissueCooldown: time.Second, IssueActorAttemptsPerMinute: 30, IssueProjectAttemptsPerMinute: 100},
			Change:       accountemail.EmailChangeConfig{Enabled: true, ConfirmURL: origin + "/change", ReportURL: origin + "/report", RecoveryURL: origin + "/recover", TTL: 30 * time.Minute, ProtectionTTL: 24 * time.Hour, RecoveryTTL: 30 * time.Minute}, FreshAuthTTL: 5 * time.Minute,
		}
		f.configs[i] = cfg
		f.services[i], err = appauth.NewProjectEmail(ctx, key, cfg, allowed, appauth.ProjectEmailDependencies{ProjectSMTPDependencies: deps, Hash: projects.deps.Hash})
		require.NoError(t, err)
		f.trackLimits(t, i, scope)
	}
	t.Cleanup(func() { f.cleanup(t, ctx) })
	return f
}

func (f *emailIsolationFixture) trackLimits(t *testing.T, i int, scope realmscope.Scope) {
	t.Helper()
	groups := [2][]string{
		{
			"resend-ip:" + emailIsolationIP, "resend-email:" + httpIsolationEmail, "confirm-ip:" + emailIsolationIP,
			"invitation-reissue-actor:" + httpOwnerID, "invitation-reissue-project", "email-change-user:" + httpIsolationUser, "email-change-request-ip:" + emailIsolationIP, "email-change-confirm:" + emailIsolationIP, "email-change-report:" + emailIsolationIP,
		},
		{
			"forgot-ip:" + emailIsolationIP, "forgot-email:" + httpIsolationEmail, "reset-ip:" + emailIsolationIP, "reset-global", "activation-ip:" + emailIsolationIP, "activation-global", "protected-recovery-ip:" + emailIsolationIP,
			"temporary-password-issue-actor:" + httpOwnerID, "temporary-password-issue-project", "temporary-password-setup-ip:" + emailIsolationIP, "temporary-password-setup-project", "login-ip:" + emailIsolationIP, "login-email:isolation-temp@example.test", "login-global",
		},
	}
	for j, group := range []struct{ purpose, legacy string }{{"email-verification-limit", "auth:email-verification:limit:"}, {"password-limit", "auth:password-recovery:limit:"}} {
		prefix, err := scope.RedisPrefix(group.purpose, group.legacy)
		require.NoError(t, err)
		for _, logical := range groups[j] {
			f.projects.redisKeys[prefix+f.ciphers[i][j].Digest(logical)] = struct{}{}
		}
	}
}

func (f *emailIsolationFixture) cleanup(t *testing.T, ctx context.Context) {
	t.Helper()
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	for i, db := range f.projects.databases {
		users := append([]string{httpIsolationUser, httpOwnerID}, f.users[i]...)
		for _, table := range []string{"email_verification_audit", "password_audit", "email_change_audit", "invitation_audit", "email_changes", "temporary_password_credentials"} {
			_, err := db.Exec(cleanup, `DELETE FROM auth.`+table+` WHERE user_id=ANY($1::uuid[])`, users)
			require.NoError(t, err)
		}
		_, err := db.Exec(cleanup, `DELETE FROM auth.account_provisions WHERE actor_id=$1`, httpOwnerID)
		require.NoError(t, err)
		_, err = db.Exec(cleanup, `DELETE FROM auth.users WHERE id=ANY($1::uuid[])`, f.users[i])
		require.NoError(t, err)
		_, err = db.Exec(cleanup, `DELETE FROM auth.smtp_settings; INSERT INTO auth.smtp_settings SELECT * FROM isolation_smtp_before`)
		require.NoError(t, err)
	}
}
