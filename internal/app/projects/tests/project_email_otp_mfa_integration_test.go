package projects_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"

	projectdelivery "github.com/Inforberi/financial-intelligence/internal/app/projects/delivery"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/app/projects/methods"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

func (f projectOTPFixture) mfa(t *testing.T, ctx context.Context, listener net.Listener) {
	t.Helper()
	purpose, err := f.scope.Purpose("mfa:v1")
	require.NoError(t, err)
	cipher, err := secretbox.NewScoped(f.root, purpose)
	require.NoError(t, err)
	const secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	for _, user := range otpFixtureUsers[2:] {
		encrypted, err := cipher.Seal([]byte(user + "\x00" + secret))
		require.NoError(t, err)
		_, err = f.db.Exec(ctx, `INSERT INTO auth.mfa_totp(user_id,secret,last_step) VALUES($1,$2,0)`, user, encrypted)
		require.NoError(t, err)
	}
	f.cfg.MFA = mfaservice.Config{Enabled: true, Issuer: "Project OTP fixture", ChallengeTTL: time.Minute, UserLimitPerMinute: 100, IPLimitPerMinute: 100, GlobalLimitPerMinute: 100}
	svc, err := projectmethods.NewProjectEmailOTP(ctx, f.key, f.cfg, []string{listener.Addr().String()}, f.deps)
	require.NoError(t, err)
	requested, err := svc.Request(ctx, otpFixtureEmails[2], otpFixtureIP)
	require.NoError(t, err)
	result, err := svc.Confirm(ctx, otpservice.ConfirmInput{Code: f.code(t, ctx, requested.Binding, ""), Binding: requested.Binding, IP: otpFixtureIP})
	require.NoError(t, err)
	require.Empty(t, result.RawToken)
	require.NotNil(t, result.Challenge)
	prefix, err := f.scope.RedisPrefix("mfa-limit", "auth:mfa:limit:")
	require.NoError(t, err)
	keys := []string{prefix + cipher.Digest("user:"+otpFixtureUsers[2]), prefix + cipher.Digest("login:factor-user:"+otpFixtureUsers[2]), prefix + "login:ip:" + cipher.Digest(otpFixtureIP), prefix + "project", prefix + "login:complete:subject:" + cipher.Digest(result.Challenge.Token+":"+result.Challenge.Binding)}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		require.NoError(t, f.rdb.Del(cleanup, keys...).Err())
	})
	var sessions int
	require.NoError(t, f.db.QueryRow(ctx, `SELECT count(*) FROM auth.sessions WHERE user_id=$1`, otpFixtureUsers[2]).Scan(&sessions))
	require.Zero(t, sessions)
	var now time.Time
	require.NoError(t, f.db.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now))
	code, err := totp.GenerateCode(secret, now)
	require.NoError(t, err)
	input := mfalogin.CompleteLoginInput{Token: result.Challenge.Token, Binding: result.Challenge.Binding, Code: code, IP: otpFixtureIP, UserAgent: "project OTP MFA fixture"}
	completed, err := svc.CompleteMFA(ctx, input)
	require.NoError(t, err)
	require.NotEmpty(t, completed.Token)
	require.False(t, completed.MFAVerified.IsZero())
	completed, err = svc.CompleteMFA(ctx, input)
	require.Error(t, err)
	require.Nil(t, completed)
	f.cfg.MFA = mfaservice.Config{}
	svc, err = projectmethods.NewProjectEmailOTP(ctx, f.key, f.cfg, []string{listener.Addr().String()}, f.deps)
	require.NoError(t, err)
	requested, err = svc.Request(ctx, otpFixtureEmails[3], otpFixtureIP)
	require.NoError(t, err)
	result, err = svc.Confirm(ctx, otpservice.ConfirmInput{Code: f.code(t, ctx, requested.Binding, ""), Binding: requested.Binding, IP: otpFixtureIP})
	require.Error(t, err)
	require.Nil(t, result)
	require.NoError(t, f.db.QueryRow(ctx, `SELECT count(*) FROM auth.sessions WHERE user_id=$1`, otpFixtureUsers[3]).Scan(&sessions))
	require.Zero(t, sessions)
}

func (f projectOTPFixture) delivery(t *testing.T, ctx context.Context, listener net.Listener, binding string) {
	t.Helper()
	runner, err := projectdelivery.NewProjectDelivery(projectdelivery.ProjectDeliveryConfig{Parallelism: 1, PageSize: 1, Interval: time.Second, SMTPAllowedTargets: []string{listener.Addr().String()}}, f.deps)
	require.NoError(t, err)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	released := make(chan struct{})
	close(released)
	smtpDone := make(chan error, 1)
	go projectSMTPGreeting(runCtx, listener, make(chan struct{}), released, smtpDone)
	reports := make(chan error, 1)
	done := make(chan error, 1)
	go func() {
		done <- runner.Run(runCtx, func(err error) {
			select {
			case reports <- err:
			case <-runCtx.Done():
			}
		})
	}()
	smtpDrained := false
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(6 * time.Second):
			t.Error("OTP scheduler did not drain")
		}
		if !smtpDrained {
			select {
			case err := <-smtpDone:
				if !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) {
					require.NoError(t, err)
				}
			case <-time.After(6 * time.Second):
				t.Error("OTP SMTP fixture did not drain")
			}
		}
	})
	timer := time.NewTimer(8 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-reports:
			var retried bool
			require.NoError(t, f.db.QueryRow(ctx, `SELECT attempts=1 AND lease IS NULL AND available_at>clock_timestamp() FROM auth.email_login_outbox WHERE digest=$1`, f.cipher.Digest("binding:"+binding)).Scan(&retried))
			if retried {
				select {
				case err := <-smtpDone:
					smtpDrained = true
					require.NoError(t, err)
				case <-timer.C:
					t.Fatal("OTP SMTP fixture did not finish")
				}
				return
			}
		case <-timer.C:
			t.Fatal("project OTP delivery did not retry safely without STARTTLS")
		}
	}
}
