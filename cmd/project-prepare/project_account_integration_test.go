package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	appauth "github.com/Inforberi/financial-intelligence/internal/app/auth"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
)

type projectAccountFixture struct {
	admin      *pgx.Conn
	sourceUser string
	password   string
	db         *pgx.Conn
	rdb        *redis.Client
	key        projectruntime.Key
	deps       appauth.ProjectSMTPDependencies
	hash       *hasher.Bounded
	cfg        appauth.ProjectEmailConfig
	listener   net.Listener
	ciphers    []*secretbox.Cipher
}

func (f projectAccountFixture) run(t *testing.T, ctx context.Context) {
	t.Helper()
	const actorID = "f8300000-0000-4000-8000-000000000001"
	const bindID = "f8300000-0000-4000-8000-000000000002"
	const changeID = "f8300000-0000-4000-8000-000000000003"
	const oldEmail = "runtime-account-change@example.test"
	const newEmail = "runtime-account-new@example.test"
	const bindEmail = "runtime-account-bind@example.test"
	const tempEmail = "runtime-account-temporary@example.test"
	const inviteEmail = "runtime-account-invited@example.test"
	const ip = "192.0.2.83"

	users := []string{actorID, bindID, changeID}
	tokens := tokengenerate.New()
	actorToken, err := tokens.GenerateToken()
	require.NoError(t, err)
	bindingToken, err := tokens.GenerateToken()
	require.NoError(t, err)
	changeToken, err := tokens.GenerateToken()
	require.NoError(t, err)
	actorHash, bindingHash, changeHash := tokens.Hash(actorToken), tokens.Hash(bindingToken), tokens.Hash(changeToken)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	f.listener = listener
	t.Cleanup(func() {
		err := listener.Close()
		if !errors.Is(err, net.ErrClosed) {
			require.NoError(t, err)
		}
	})
	_, rawPort, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(rawPort)
	require.NoError(t, err)
	// Synthetic backend session/MFA proofs; real callers obtain them through authentication.
	_, err = f.db.Exec(ctx, `CREATE TEMP TABLE account_policy_before AS TABLE auth.auth_settings;
 CREATE TEMP TABLE account_smtp_before AS TABLE auth.smtp_settings;
 UPDATE auth.smtp_settings SET configuration=jsonb_set(configuration,'{port}',to_jsonb($11::int));
 UPDATE auth.auth_settings SET password_enabled=true,password_email_verification='disabled';
 INSERT INTO auth.users(id) VALUES($1),($2),($3);
 INSERT INTO auth.user_emails(user_id,email,verified_at) VALUES($3,$4,clock_timestamp());
 INSERT INTO auth.password_credentials(user_id,email_id,password_hash)
 SELECT $3,e.id,p.password_hash FROM auth.user_emails e CROSS JOIN auth.password_credentials p
 WHERE e.user_id=$3 AND p.user_id=$12::uuid;
 INSERT INTO auth.roles(key,name) VALUES('project_account_fixture_manager','Fixture manager');
 INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,$5 FROM auth.roles WHERE key='project_account_fixture_manager';
 INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,$6 FROM auth.roles WHERE key='project_account_fixture_manager';
 INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM auth.roles WHERE key='project_account_fixture_manager';
 INSERT INTO auth.mfa_totp(user_id,secret,last_step) VALUES($1,$7,0);
 INSERT INTO auth.linked_identities(user_id,issuer,subject) VALUES($2,'https://accounts.google.com','project-account-binding');
 INSERT INTO auth.sessions(token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,password_verified_at,primary_method,primary_verified_at,mfa_verified_at,user_agent,ip_address)
 VALUES($8,$1,1,clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours',clock_timestamp(),'password',clock_timestamp(),clock_timestamp(),'project-account-fixture',$13),
 ($9,$2,1,clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours',NULL,'oidc',clock_timestamp(),NULL,'project-account-fixture',$13),
 ($10,$3,1,clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours',clock_timestamp(),'password',clock_timestamp(),NULL,'project-account-fixture',$13)`, actorID, bindID, changeID, oldEmail, string(accesssettings.UsersManage), string(accesssettings.EmailBindingManage), make([]byte, 48), actorHash, bindingHash, changeHash, port, f.sourceUser, ip)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, err := f.db.Exec(cleanup, `DELETE FROM auth.email_bindings WHERE user_id=ANY($1::uuid[]) OR actor_id=$2;
	DELETE FROM auth.email_verification_audit WHERE user_id=ANY($1::uuid[]) OR actor_id=$2;
	DELETE FROM auth.password_audit WHERE user_id=ANY($1::uuid[]) OR actor_id=$2;
   DELETE FROM auth.email_change_audit WHERE user_id=ANY($1::uuid[]);
   DELETE FROM auth.email_changes WHERE user_id=ANY($1::uuid[]);
   DELETE FROM auth.invitation_audit WHERE user_id=ANY($1::uuid[]) OR actor_id=$2;
   DELETE FROM auth.temporary_password_reissues WHERE actor_id=$2;
   DELETE FROM auth.invitation_reissues WHERE actor_id=$2;
   DELETE FROM auth.temporary_password_credentials WHERE user_id=ANY($1::uuid[]);
   DELETE FROM auth.account_provisions WHERE actor_id=$2;
   DELETE FROM auth.sessions WHERE user_id=ANY($1::uuid[]);
   DELETE FROM auth.user_roles WHERE user_id=ANY($1::uuid[]);
   DELETE FROM auth.users WHERE id=ANY($1::uuid[]);
   DELETE FROM auth.role_permissions WHERE role_id IN(SELECT id FROM auth.roles WHERE key='project_account_fixture_manager');
   DELETE FROM auth.roles WHERE key='project_account_fixture_manager';
   DELETE FROM auth.auth_settings; INSERT INTO auth.auth_settings SELECT * FROM account_policy_before;
   DELETE FROM auth.smtp_settings; INSERT INTO auth.smtp_settings SELECT * FROM account_smtp_before`, users, actorID)
		require.NoError(t, err)
	})
	actor := accessservice.Principal{UserID: actorID, TokenHash: actorHash}
	scope, err := realmscope.New("project", string(f.key.Binding.ProjectID))
	require.NoError(t, err)
	var keys []string
	for index, group := range []struct {
		purpose, legacy string
		logical         []string
	}{
		{"email-verification-limit", "auth:email-verification:limit:", []string{
			"invitation-reissue-actor:" + actorID, "invitation-reissue-actor:" + bindID, "invitation-reissue-project",
			"email-binding:request:actor:" + actorID, "email-binding:request:ip:" + ip, "email-binding:request:project", "email-binding:request:user:" + bindID,
			"email-binding:request:actor:" + changeID,
			"email-binding:confirm:ip:" + ip, "email-binding:confirm:user:" + bindID, "email-binding:confirm:project",
			"email-change-user:" + changeID, "email-change-request-ip:" + ip, "email-change-confirm:" + ip, "email-change-report:" + ip,
			"email-binding:request:ip:127.0.0.1", "email-binding:confirm:ip:127.0.0.1",
			"email-change-request-ip:127.0.0.1", "email-change-confirm:127.0.0.1", "email-change-report:127.0.0.1",
		}},
		{"password-limit", "auth:password-recovery:limit:", []string{
			"activation-ip:" + ip, "activation-global", "protected-recovery-ip:" + ip,
			"protected-recovery-ip:127.0.0.1",
			"temporary-password-issue-actor:" + actorID, "temporary-password-issue-project", "temporary-password-setup-ip:" + ip, "temporary-password-setup-project",
			"login-ip:" + ip, "login-email:" + tempEmail, "login-global",
		}},
	} {
		prefix, err := scope.RedisPrefix(group.purpose, group.legacy)
		require.NoError(t, err)
		for _, logical := range group.logical {
			keys = append(keys, prefix+f.ciphers[index].Digest(logical))
		}
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		require.NoError(t, f.rdb.Del(cleanup, keys...).Err())
	})
	cfg := f.cfg
	cfg.Invitations = accountservice.InvitationConfig{Enabled: true, URL: cfg.Origin + "/activate", TTL: time.Hour, ActivationGlobalLimit: 100, ReissueCooldown: time.Second, IssueActorAttemptsPerMinute: 30, IssueProjectAttemptsPerMinute: 100}
	cfg.Binding = accountservice.EmailBindingConfig{Enabled: true, TTL: 5 * time.Minute, RequestsPerMinute: 100, ConfirmationsPerMinute: 1000}
	cfg.Change = accountservice.EmailChangeConfig{Enabled: true, ConfirmURL: cfg.Origin + "/change", ReportURL: cfg.Origin + "/report", RecoveryURL: cfg.Origin + "/recover", TTL: 30 * time.Minute, ProtectionTTL: 24 * time.Hour, RecoveryTTL: 30 * time.Minute}
	cfg.FreshAuthTTL = 5 * time.Minute
	service, err := appauth.NewProjectEmail(ctx, f.key, cfg, []string{f.listener.Addr().String()}, appauth.ProjectEmailDependencies{ProjectSMTPDependencies: f.deps, Hash: f.hash})
	require.NoError(t, err)
	input := accountservice.ProvisionInput{Actor: actor, IdempotencyKey: "f8300000-0000-4000-8000-000000000011", Email: inviteEmail, Invite: true}
	invited, err := service.ProvisionUser(ctx, input)
	require.NoError(t, err)
	users = append(users, string(invited.UserID))
	replay, err := service.ProvisionUser(ctx, input)
	require.NoError(t, err)
	require.True(t, replay.Reused)
	require.Equal(t, invited.UserID, replay.UserID)
	var payload []byte
	require.NoError(t, f.db.QueryRow(ctx, `SELECT o.payload FROM auth.invitation_outbox o JOIN auth.account_invitations i USING(digest) WHERE i.user_id=$1`, invited.UserID).Scan(&payload))
	oldToken := accountMessageToken(t, f.ciphers[0], payload)
	_, err = f.db.Exec(ctx, `UPDATE auth.account_provisions SET last_invited_at=clock_timestamp()-interval '2 minutes' WHERE user_id=$1`, invited.UserID)
	require.NoError(t, err)
	_, err = service.ReissueInvitation(ctx, accountservice.InvitationReissueInput{Actor: actor, UserID: invited.UserID, IdempotencyKey: "f8300000-0000-4000-8000-000000000012"})
	require.NoError(t, err)
	require.Error(t, service.ActivateInvitation(ctx, oldToken, f.password, f.password, ip))
	require.NoError(t, f.db.QueryRow(ctx, `SELECT o.payload FROM auth.invitation_outbox o JOIN auth.account_invitations i USING(digest) WHERE i.user_id=$1`, invited.UserID).Scan(&payload))
	inviteToken := accountMessageToken(t, f.ciphers[0], payload)
	bad := input
	bad.IdempotencyKey = "f8300000-0000-4000-8000-000000000013"
	bad.Actor.UserID = bindID
	bad.Email = "forbidden-project-account@example.test"
	denied, err := service.ProvisionUser(ctx, bad)
	require.Error(t, err)
	require.Nil(t, denied)
	web, origin, stopDelivery := f.httpAccountManagement(t, ctx, cfg)
	path := "/api/v1/admin/users/" + bindID + "/email-binding"
	status, _ := web(path, "", actorToken, `!`)
	require.Equal(t, 403, status)
	status, _ = web(path, origin, "", `!`)
	require.Equal(t, 401, status)
	status, _ = web(path, origin, bindingToken, `{"email":"`+bindEmail+`"}`)
	require.Equal(t, 409, status, "target session cannot approve its own email")
	status, _ = web(path, origin, changeToken, `{"email":"`+bindEmail+`"}`)
	require.Equal(t, 403, status, "another ordinary user cannot approve email binding")
	status, _ = web(path, origin, actorToken, `{"email":"`+bindEmail+`"}`)
	require.Equal(t, 202, status)
	require.NoError(t, f.db.QueryRow(ctx, `SELECT payload FROM auth.email_bindings WHERE user_id=$1`, bindID).Scan(&payload))
	plain, err := f.ciphers[0].Open(payload)
	require.NoError(t, err)
	var binding struct{ Body string }
	require.NoError(t, json.Unmarshal(plain, &binding))
	clear(plain)
	code := regexp.MustCompile(`<strong>([0-9]{8})</strong>`).FindStringSubmatch(binding.Body)
	require.Len(t, code, 2)
	status, _ = web("/api/v1/auth/email/change", origin, changeToken, `{"email":"`+newEmail+`","password":"`+f.password+`"}`)
	require.Equal(t, 202, status)
	require.NoError(t, f.db.QueryRow(ctx, `SELECT o.payload FROM auth.email_change_outbox o JOIN auth.email_changes c ON c.id=o.change_id WHERE c.user_id=$1 AND kind='confirm'`, changeID).Scan(&payload))
	confirmToken := accountMessageToken(t, f.ciphers[0], payload)
	require.NoError(t, f.db.QueryRow(ctx, `SELECT o.payload FROM auth.email_change_outbox o JOIN auth.email_changes c ON c.id=o.change_id WHERE c.user_id=$1 AND kind='notice'`, changeID).Scan(&payload))
	reportToken := accountMessageToken(t, f.ciphers[0], payload)
	f.delivery(t, ctx, invited.UserID, bindID, changeID)
	require.NoError(t, service.ActivateInvitation(ctx, inviteToken, f.password, f.password, ip))
	require.Error(t, service.ActivateInvitation(ctx, inviteToken, f.password, f.password, ip))
	proof := mfaservice.Proof{UserID: bindID, TokenHash: bindingHash, AuthVersion: 1}
	status, cookies := web("/api/v1/auth/email/binding/confirm", origin, bindingToken, `{"code":"`+code[1]+`"}`)
	require.Equal(t, 200, status)
	require.NotEmpty(t, cookies)
	for _, cookie := range cookies {
		require.Empty(t, cookie.Value, "binding revokes sessions instead of issuing one")
	}
	require.Error(t, service.ConfirmEmailBinding(ctx, proof, code[1], ip))
	status, cookies = web("/api/v1/auth/email/change/confirm", origin, "", `{"token":"`+confirmToken+`"}`)
	require.Equal(t, 200, status)
	require.NotEmpty(t, cookies)
	status, _ = web("/api/v1/auth/email/change/confirm", origin, "", `{"token":"`+confirmToken+`"}`)
	require.Equal(t, 400, status)
	stopDelivery()
	_, err = f.db.Exec(ctx, `DELETE FROM auth.smtp_settings; UPDATE auth.auth_settings SET version=version+1`)
	require.NoError(t, err)
	status, _ = web("/api/v1/auth/email/change/report", origin, "", `{"token":"`+reportToken+`"}`)
	require.Equal(t, 404, status, "stale profile is rejected before token consumption")
	status, _ = web("/api/v1/auth/email/change/report", origin, "", `{"token":"`+reportToken+`"}`)
	require.Equal(t, 200, status, "protective reporting survives worker and SMTP unavailability")
	require.NoError(t, f.db.QueryRow(ctx, `SELECT o.payload FROM auth.email_change_outbox o JOIN auth.email_changes c ON c.id=o.change_id WHERE c.user_id=$1 AND kind='recovery'`, changeID).Scan(&payload))
	recoveryToken := accountMessageToken(t, f.ciphers[0], payload)
	const recoveredPassword = "Synthetic-account-recovered-password-83!"
	status, cookies = web("/api/v1/auth/email/change/recover", origin, "", `{"token":"`+recoveryToken+`","newPassword":"`+recoveredPassword+`","confirmPassword":"`+recoveredPassword+`"}`)
	require.Equal(t, 200, status)
	for _, cookie := range cookies {
		require.Empty(t, cookie.Value, "protected recovery must not issue a session")
	}
	require.Error(t, service.RecoverEmailChange(ctx, recoveryToken, recoveredPassword, recoveredPassword, ip))
	var restored, restoredHash, accountStatus string
	require.NoError(t, f.db.QueryRow(ctx, `SELECT e.email,p.password_hash,u.status FROM auth.password_credentials p JOIN auth.user_emails e ON e.id=p.email_id JOIN auth.users u ON u.id=p.user_id WHERE p.user_id=$1`, changeID).Scan(&restored, &restoredHash, &accountStatus))
	require.Equal(t, oldEmail, restored)
	require.Equal(t, "active", accountStatus)
	require.NoError(t, f.hash.Compare(ctx, recoveredPassword, restoredHash))
	temporaryCfg := projectPasswordFixtureConfig()
	temporaryCfg.TemporaryPassword = passwordservice.TemporaryPasswordConfig{Enabled: true, TTL: time.Hour, SetupTTL: 5 * time.Minute, ReissueCooldown: time.Second, IssueActorAttemptsPerMinute: 30, IssueProjectAttemptsPerMinute: 100, SetupProjectAttemptsPerMinute: 100}
	passwords, err := appauth.NewProjectPassword(ctx, f.key, temporaryCfg, appauth.ProjectPasswordDependencies{Registry: f.deps.Registry, Reader: f.deps.Reader, Redis: f.rdb, Hash: f.hash})
	require.NoError(t, err)
	temporaryInput := passwordservice.TemporaryProvisionInput{Actor: actor, IdempotencyKey: "f8300000-0000-4000-8000-000000000021", Email: tempEmail}
	temporary, err := passwords.ProvisionTemporaryPassword(ctx, temporaryInput)
	require.NoError(t, err)
	users = append(users, string(temporary.UserID))
	require.NotEmpty(t, temporary.Password)
	encoded, err := json.Marshal(temporary)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), temporary.Password)
	repeated, err := passwords.ProvisionTemporaryPassword(ctx, temporaryInput)
	require.NoError(t, err)
	require.True(t, repeated.Reused)
	require.Empty(t, repeated.Password)
	_, err = f.db.Exec(ctx, `UPDATE auth.account_provisions SET temporary_password_issued_at=clock_timestamp()-interval '2 minutes' WHERE user_id=$1`, temporary.UserID)
	require.NoError(t, err)
	fresh, err := passwords.ReissueTemporaryPassword(ctx, passwordservice.TemporaryReissueInput{Actor: actor, UserID: temporary.UserID, IdempotencyKey: "f8300000-0000-4000-8000-000000000022"})
	require.NoError(t, err)
	require.NotEmpty(t, fresh.Password)
	_, err = passwords.BeginTemporaryPassword(ctx, tempEmail, temporary.Password, ip)
	require.Error(t, err)
	setup, err := passwords.BeginTemporaryPassword(ctx, tempEmail, fresh.Password, ip)
	require.NoError(t, err)
	require.Len(t, setup.Token, 43)
	require.NoError(t, passwords.CompleteTemporaryPassword(ctx, setup.Token, f.password, f.password, ip))
	require.Error(t, passwords.CompleteTemporaryPassword(ctx, setup.Token, f.password, f.password, ip))
	session, err := passwords.Login(ctx, passwordservice.LoginInput{Email: tempEmail, Password: f.password, IP: ip, UserAgent: "account fixture"})
	require.NoError(t, err)
	require.NotEmpty(t, session.Token)
}

func accountMessageToken(t *testing.T, cipher *secretbox.Cipher, payload []byte) string {
	t.Helper()
	plain, err := cipher.Open(payload)
	require.NoError(t, err)
	var message struct{ Body string }
	require.NoError(t, json.Unmarshal(plain, &message))
	clear(plain)
	match := regexp.MustCompile(`#token=([A-Za-z0-9_-]{43})`).FindStringSubmatch(message.Body)
	require.Len(t, match, 2)
	return match[1]
}
