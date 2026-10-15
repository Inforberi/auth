package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfatotp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func mfaManagement(t *testing.T, db *pgxpool.Pool) *mfaservice.Service {
	t.Helper()
	cipher, err := secretbox.NewScoped(base64.StdEncoding.EncodeToString(make([]byte, 32)), "mfa:v1")
	if err != nil {
		t.Fatal(err)
	}
	svc, err := mfaservice.NewConfigured(mfapostgres.New(db), cipher, mfatotp.Authenticator{}, mfaTestLimit{}, tokengenerate.New(), mfaservice.Config{
		Enabled: true, Issuer: "Auth", ChallengeTTL: 5 * time.Minute, UserLimitPerMinute: 5, IPLimitPerMinute: 10, GlobalLimitPerMinute: 500,
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func managementProof(t *testing.T, ctx context.Context, f mfaLoginFixture) mfaservice.Proof {
	t.Helper()
	result, err := f.login.Complete(ctx, f.start(t, ctx))
	if err != nil {
		t.Fatal(err)
	}
	tokens := tokengenerate.New()
	replacement := tokens.Hash("mfa-management-" + string(f.user))
	if _, err := f.sessions.ConfirmPassword(ctx, f.user, tokens.Hash(result.Token), "old-hash", 2, replacement); err != nil {
		t.Fatal(err)
	}
	return mfaservice.Proof{UserID: f.user, TokenHash: replacement, AuthVersion: 2}
}

func checkMFAManagement(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	svc := mfaManagement(t, db)
	for _, action := range []string{"disable", "regenerate", "replace"} {
		t.Run(action, func(t *testing.T) {
			f := newMFALoginFixture(t, db, ctx, "management-"+action)
			proof := managementProof(t, ctx, f)
			step, err := svc.StepUp(ctx, mfaservice.StepUpInput{Proof: proof, Code: f.codes[1], Recovery: true})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.sessions.FindSession(ctx, proof.TokenHash); err == nil {
				t.Fatal("step-up did not rotate session")
			}
			proof.TokenHash = tokengenerate.New().Hash(step.Token)
			session, err := f.sessions.FindSession(ctx, proof.TokenHash)
			if err != nil || session.MFAVerifiedAt == nil || !session.MFAVerifiedAt.Equal(step.VerifiedAt) {
				t.Fatal("step-up context", err)
			}
			switch action {
			case "disable":
				if err := svc.Disable(ctx, proof); err != nil {
					t.Fatal(err)
				}
			case "regenerate":
				codes, err := svc.RegenerateRecovery(ctx, proof)
				if err != nil || len(codes.Codes) != 10 {
					t.Fatal(err)
				}
				if _, err := svc.Verify(ctx, mfaservice.VerifyInput{UserID: f.user, AuthVersion: 3, Recovery: true, Code: f.codes[2]}); !errors.Is(err, mfadomain.ErrInvalidCode) {
					t.Fatal("old recovery survived regeneration", err)
				}
				if _, err := svc.Verify(ctx, mfaservice.VerifyInput{UserID: f.user, AuthVersion: 3, Recovery: true, Code: codes.Codes[0]}); err != nil {
					t.Fatal("new recovery unavailable", err)
				}
			case "replace":
				enrollment, err := svc.StartReplacement(ctx, proof)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := svc.ConfirmEnrollment(ctx, mfaservice.ConfirmInput{Proof: proof, Token: enrollment.Token, Code: mfaCode(t, db, ctx, enrollment.Secret, 0)}); !errors.Is(err, mfadomain.ErrInvalidCode) {
					t.Fatal("replacement used as enrollment", err)
				}
				codes, err := svc.ConfirmReplacement(ctx, mfaservice.ConfirmInput{Proof: proof, Token: enrollment.Token, Code: mfaCode(t, db, ctx, enrollment.Secret, 0)})
				if err != nil || len(codes.Codes) != 10 {
					t.Fatal(err)
				}
				if _, err := svc.Verify(ctx, mfaservice.VerifyInput{UserID: f.user, AuthVersion: 3, Recovery: true, Code: f.codes[2]}); !errors.Is(err, mfadomain.ErrInvalidCode) {
					t.Fatal("old factor recovery survived", err)
				}
			}
			if _, err := f.sessions.FindSession(ctx, proof.TokenHash); err == nil {
				t.Fatal("management did not revoke sessions")
			}
			var version int64
			var enabled bool
			if err := db.QueryRow(ctx, `SELECT auth_version,EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1) FROM auth.users WHERE id=$1`, f.user).Scan(&version, &enabled); err != nil || version != 3 || enabled != (action != "disable") {
				t.Fatal("factor transition", version, enabled, err)
			}
		})
	}
	t.Run("freshness-and-admin-policy", func(t *testing.T) {
		f := newMFALoginFixture(t, db, ctx, "management-guards")
		proof := managementProof(t, ctx, f)
		accessExec(t, db, ctx, `UPDATE auth.sessions SET mfa_verified_at=NULL WHERE token_hash=$1`, proof.TokenHash)
		if err := svc.Disable(ctx, proof); !errors.Is(err, mfadomain.ErrProofRequired) {
			t.Fatal("password bypassed MFA", err)
		}
		if _, err := svc.StartReplacement(ctx, proof); !errors.Is(err, mfadomain.ErrProofRequired) {
			t.Fatal("replace without factor proof", err)
		}
		step, err := svc.StepUp(ctx, mfaservice.StepUpInput{Proof: proof, Recovery: true, Code: f.codes[1]})
		if err != nil {
			t.Fatal(err)
		}
		proof.TokenHash = tokengenerate.New().Hash(step.Token)
		accessExec(t, db, ctx, `INSERT INTO auth.roles(key,name) VALUES ('mfa_guard_admin','MFA administrator')`)
		accessExec(t, db, ctx, `INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,'access.roles.manage' FROM auth.roles WHERE key='mfa_guard_admin'`)
		accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM auth.roles WHERE key='mfa_guard_admin'`, f.user)
		defer func() {
			accessExec(t, db, ctx, `DELETE FROM auth.user_roles WHERE user_id=$1 AND role_id IN (SELECT id FROM auth.roles WHERE key='mfa_guard_admin')`, f.user)
			accessExec(t, db, ctx, `DELETE FROM auth.roles WHERE key='mfa_guard_admin'`)
		}()
		for _, permission := range []string{"access.roles.manage", "accounts.users.status.manage", "accounts.users.delete"} {
			accessExec(t, db, ctx, `UPDATE auth.role_permissions SET permission_key=$1 WHERE role_id IN (SELECT id FROM auth.roles WHERE key='mfa_guard_admin')`, permission)
			if err := svc.Disable(ctx, proof); !errors.Is(err, mfadomain.ErrRequiredByPolicy) {
				t.Fatal("administrator disabled MFA", permission, err)
			}
		}
		if err := mfapostgres.New(db).CheckDisabled(ctx); err == nil {
			t.Fatal("disabled operational MFA accepts enrolled factors")
		}
		accessExec(t, db, ctx, `UPDATE auth.sessions SET password_verified_at=clock_timestamp()-interval '6 minutes' WHERE token_hash=$1`, proof.TokenHash)
		if _, err := svc.RegenerateRecovery(ctx, proof); !errors.Is(err, mfadomain.ErrProofRequired) {
			t.Fatal("stale password proof accepted", err)
		}
	})
	t.Run("atomic-management-rollback", func(t *testing.T) {
		f := newMFALoginFixture(t, db, ctx, "management-rollback")
		proof := managementProof(t, ctx, f)
		accessExec(t, db, ctx, `CREATE FUNCTION auth.reject_mfa_management_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
			IF NEW.event IN ('mfa_step_up','totp_disabled','recovery_regenerated','totp_replaced') THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END; $$;
			CREATE TRIGGER reject_mfa_management_audit BEFORE INSERT ON auth.mfa_audit FOR EACH ROW EXECUTE FUNCTION auth.reject_mfa_management_audit()`)
		defer accessExec(t, db, ctx, `DROP TRIGGER reject_mfa_management_audit ON auth.mfa_audit;DROP FUNCTION auth.reject_mfa_management_audit()`)
		if result, err := svc.StepUp(ctx, mfaservice.StepUpInput{Proof: proof, Recovery: true, Code: f.codes[1]}); err == nil || result != nil {
			t.Fatal("step-up accepted without audit")
		}
		if err := svc.Disable(ctx, proof); err == nil {
			t.Fatal("disable accepted without audit")
		}
		if result, err := svc.RegenerateRecovery(ctx, proof); err == nil || result != nil {
			t.Fatal("recovery secrets returned before commit")
		}
		var factor bool
		var count int
		var version int64
		if err := db.QueryRow(ctx, `SELECT auth_version,EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1),
			(SELECT count(*) FROM auth.mfa_recovery_codes WHERE user_id=$1) FROM auth.users WHERE id=$1`, f.user).Scan(&version, &factor, &count); err != nil || version != 2 || !factor || count != 9 {
			t.Fatal("partial management rollback", version, factor, count, err)
		}
		if _, err := f.sessions.FindSession(ctx, proof.TokenHash); err != nil {
			t.Fatal("rollback revoked caller session", err)
		}
	})
}
