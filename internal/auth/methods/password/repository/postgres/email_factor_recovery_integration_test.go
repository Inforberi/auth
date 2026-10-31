package postgres

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfatotp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func TestEmailFactorRecoverySchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	accessExec(t, db, ctx, `CREATE ROLE auth_mfa_recovery_operator NOLOGIN;
 CREATE ROLE auth_mfa_email_operator LOGIN PASSWORD 'synthetic-recovery-only';
 CREATE ROLE auth_mfa_email_runtime LOGIN PASSWORD 'synthetic-recovery-only'`)
	t.Cleanup(func() {
		migrateFixture(t, db, ctx, "down")
		accessExec(t, db, ctx, `REVOKE CONNECT ON DATABASE auth_schema_test FROM auth_mfa_recovery_operator;
 REVOKE CONNECT ON DATABASE auth_schema_test FROM auth_mfa_email_runtime;
 DROP ROLE auth_mfa_email_runtime; DROP ROLE auth_mfa_email_operator; DROP ROLE auth_mfa_recovery_operator`)
	})
	grants, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..", "..", "deploy", "mfa-recovery-grants.sql"))
	require.NoError(t, err)
	accessExec(t, db, ctx, strings.ReplaceAll(string(grants), "ON DATABASE auth TO", "ON DATABASE auth_schema_test TO"))
	accessExec(t, db, ctx, `GRANT auth_mfa_recovery_operator TO auth_mfa_email_operator;
 GRANT CONNECT ON DATABASE auth_schema_test TO auth_mfa_email_runtime;
 GRANT USAGE ON SCHEMA auth TO auth_mfa_email_runtime;
 UPDATE auth.mfa_settings SET email_factor_allowed=true WHERE singleton`)
	op := mfapostgres.New(operatorPool(t, ctx, db, "auth_mfa_email_operator"))
	runtime := mfapostgres.New(operatorPool(t, ctx, db, "auth_mfa_email_runtime"))
	f := newEmailFactorLoginFixture(t, db, ctx, "lost-mail")
	accessExec(t, db, ctx, `UPDATE auth.mfa_email SET suspended_at=clock_timestamp() WHERE user_id=$1`, f.user)
	login, err := mfaservice.NewLogin(mfapostgres.New(db), recoveryCipher(t), mfatotp.Authenticator{}, mfaTestLimit{}, tokengenerate.New(), emailFactorLoginConfig())
	require.NoError(t, err)
	primary, err := login.Start(ctx, f.proof, "192.0.2.1")
	require.NoError(t, err)
	require.True(t, primary.RecoveryRequired)
	require.False(t, primary.EnrollmentRequired)
	svc := recoveryService(t, db, nil)
	candidate, err := svc.Start(ctx, mfaservice.StartRecoveryInput{Token: primary.Token, Binding: primary.Binding, IP: "192.0.2.1"})
	require.NoError(t, err)
	completion := mfaservice.CompleteRecoveryInput{
		RequestID: candidate.RequestID, Token: primary.Token, Binding: primary.Binding,
		Code: mfaCode(t, db, ctx, candidate.Secret, 0), IP: "192.0.2.1",
	}
	_, err = svc.Complete(ctx, completion)
	require.ErrorIs(t, err, mfadomain.ErrInvalidCode, "password and new authenticator alone cannot replace an enrolled factor")
	decision := mfadomain.RecoveryDecision{
		UserID: f.user, RequestID: candidate.RequestID, ExpectedVersion: f.proof.AuthVersion, Approve: true,
		Environment: "test", Reason: "INC-LOST-EMAIL",
	}
	require.ErrorIs(t, runtime.DecideRecovery(ctx, decision), mfadomain.ErrRecoveryOperatorDenied)
	require.NoError(t, op.DecideRecovery(ctx, decision))
	accessExec(t, db, ctx, `ALTER TABLE auth.mfa_audit ADD CONSTRAINT email_recovery_failure CHECK(event<>'recovery_completed') NOT VALID`)
	t.Cleanup(func() {
		accessExec(t, db, ctx, `ALTER TABLE auth.mfa_audit DROP CONSTRAINT IF EXISTS email_recovery_failure`)
	})
	_, err = svc.Complete(ctx, completion)
	require.Error(t, err)
	var email, totp bool
	require.NoError(t, db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.mfa_email WHERE user_id=$1),EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1)`, f.user).Scan(&email, &totp))
	require.True(t, email)
	require.False(t, totp)
	accessExec(t, db, ctx, `ALTER TABLE auth.mfa_audit DROP CONSTRAINT email_recovery_failure`)
	codes, err := svc.Complete(ctx, completion)
	require.NoError(t, err)
	require.Len(t, codes.Codes, mfadomain.RecoveryCodeCount)
	require.NoError(t, db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.mfa_email WHERE user_id=$1),EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1)`, f.user).Scan(&email, &totp))
	require.False(t, email)
	require.True(t, totp)
	_, err = svc.Complete(ctx, completion)
	require.ErrorIs(t, err, mfadomain.ErrInvalidCode)
	f.proof.AuthVersion++
	next, err := login.Start(ctx, f.proof, "192.0.2.1")
	require.NoError(t, err)
	require.False(t, next.RecoveryRequired)
	completed, err := login.Complete(ctx, mfaservice.CompleteLoginInput{Token: next.Token, Binding: next.Binding, Code: codes.Codes[0], Recovery: true, IP: "192.0.2.1"})
	require.NoError(t, err)
	require.NotEmpty(t, completed.Token)
}
