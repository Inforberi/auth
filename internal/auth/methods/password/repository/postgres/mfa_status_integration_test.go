package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
)

func checkMFASelfStatus(t *testing.T, db, runtime *pgxpool.Pool, ctx context.Context) {
	t.Helper()
	f := newStatusFixture(t, db, ctx, "mfa-self-status")
	proof := mfaservice.Proof{UserID: f.user, TokenHash: f.params.TokenHash, AuthVersion: 1}
	repo := mfapostgres.NewWithEmailProof(runtime, true)
	svc := mfaservice.New(repo, nil, nil, nil, "Auth")
	status, err := svc.Status(ctx, proof)
	if err != nil || status.TOTPEnabled || status.FreshPrimaryProof || status.FreshMFAProof || status.VerifiedEmail || !status.PasswordConfigured {
		t.Fatal("plain owner snapshot", status, err)
	}
	proof = mfaProof(t, db, ctx, f)
	prepareUsableAdministrator(t, db, ctx, f.user)
	accessExec(t, db, ctx, `INSERT INTO auth.mfa_recovery_codes(user_id,digest) VALUES($1,repeat('a',64)),($1,repeat('b',64))`, f.user)
	accessExec(t, db, ctx, `UPDATE auth.sessions SET created_at=clock_timestamp()-interval '10 minutes',
		primary_method='password',primary_verified_at=password_verified_at,mfa_verified_at=clock_timestamp() WHERE token_hash=$1`, proof.TokenHash)
	accessExec(t, db, ctx, `WITH r AS(INSERT INTO auth.roles(key,name,mfa_required) VALUES('status_required','Status required',true) RETURNING id)
		INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM r`, f.user)
	status, err = svc.Status(ctx, proof)
	if err != nil || !status.RequiredByRole || status.RequiredByAdministration || !status.TOTPEnabled || !status.VerifiedEmail || status.RecoveryCodesRemaining != 2 || !status.FreshPrimaryProof || !status.FreshMFAProof || !status.EmailReauthenticationEnabled {
		t.Fatal("enrolled required owner", status, err)
	}
	accessExec(t, db, ctx, `DELETE FROM auth.mfa_recovery_codes WHERE user_id=$1 AND digest=repeat('a',64)`, f.user)
	h := mfahttp.New(svc, nil, zap.NewNop())
	request := httptest.NewRequest("GET", "/api/v1/auth/mfa/status?userID=ignored", nil)
	request = request.WithContext(sessionhttp.SetAuthContext(ctx, sessionhttp.Auth{UserID: f.user, TokenHash: proof.TokenHash, AuthVersion: 1}))
	w := httptest.NewRecorder()
	h.ReadStatus(w, request)
	var response mfahttp.SecurityStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != 200 || response.DisableAllowedByPolicy || response.RecoveryCodesRemaining != 1 || !response.RequiredByRole {
		t.Fatal("owner-only HTTP snapshot", w.Code, w.Body.String(), err)
	}
	if w.Header().Get("Cache-Control") != "no-store" || len(w.Result().Cookies()) != 0 || strings.Contains(w.Body.String(), proof.TokenHash) || strings.Contains(w.Body.String(), "digest") {
		t.Fatal("status leaked/refreshed session", w.Header(), w.Body.String())
	}
	var audits int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.mfa_audit WHERE user_id=$1`, f.user).Scan(&audits); err != nil || audits != 0 {
		t.Fatal("read generated audit", audits, err)
	}
	accessExec(t, db, ctx, `UPDATE auth.sessions SET password_verified_at=statement_timestamp()-interval '6 minutes',
		primary_verified_at=statement_timestamp()-interval '6 minutes',mfa_verified_at=statement_timestamp()-interval '6 minutes' WHERE token_hash=$1`, proof.TokenHash)
	status, err = svc.Status(ctx, proof)
	if err != nil || status.FreshPrimaryProof || status.FreshMFAProof {
		t.Fatal("stale proofs blocked read or remained fresh", status, err)
	}
	accessExec(t, db, ctx, `WITH r AS(INSERT INTO auth.roles(key,name) VALUES('status_admin','Status admin') RETURNING id),
		p AS(INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,'auth.settings.manage' FROM r)
		INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM r`, f.user)
	status, err = svc.Status(ctx, proof)
	if err != nil || !status.RequiredByAdministration {
		t.Fatal("administrative policy missing", status, err)
	}
	accessExec(t, db, ctx, `DELETE FROM auth.password_credentials WHERE user_id=$1`, f.user)
	accessExec(t, db, ctx, `INSERT INTO auth.linked_identities(user_id,issuer,subject) VALUES($1,'https://synthetic.example','owner')`, f.user)
	accessExec(t, db, ctx, `UPDATE auth.sessions SET password_verified_at=NULL,email_reauthenticated_at=clock_timestamp(),
		email_reauthenticated_id=(SELECT id FROM auth.user_emails WHERE user_id=$1 AND verified_at IS NOT NULL LIMIT 1)
		WHERE token_hash=$2`, f.user, proof.TokenHash)
	status, err = svc.Status(ctx, proof)
	if err != nil || status.PasswordConfigured || !status.FreshPrimaryProof {
		t.Fatal("external owner email proof missing", status, err)
	}
	withoutEmail, err := mfapostgres.New(runtime).Status(ctx, proof)
	if err != nil || withoutEmail.FreshPrimaryProof || withoutEmail.EmailReauthenticationEnabled {
		t.Fatal("disabled email proof accepted", withoutEmail, err)
	}
	wrong := proof
	wrong.UserID = f.actor
	if _, err := svc.Status(ctx, wrong); !errors.Is(err, mfadomain.ErrProofRequired) {
		t.Fatal("foreign user accepted", err)
	}
	wrong = proof
	wrong.AuthVersion++
	if _, err := svc.Status(ctx, wrong); !errors.Is(err, mfadomain.ErrProofRequired) {
		t.Fatal("stale version accepted", err)
	}
	for _, state := range []string{"blocked", "pending"} {
		accessExec(t, db, ctx, `UPDATE auth.users SET status=$2 WHERE id=$1`, f.user, state)
		if _, err := svc.Status(ctx, proof); !errors.Is(err, mfadomain.ErrProofRequired) {
			t.Fatal("inactive account accepted", state, err)
		}
	}
	accessExec(t, db, ctx, `UPDATE auth.users SET status='active' WHERE id=$1`, f.user)
	accessExec(t, db, ctx, `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE token_hash=$1`, proof.TokenHash)
	if _, err := svc.Status(ctx, proof); !errors.Is(err, mfadomain.ErrProofRequired) {
		t.Fatal("revoked session accepted", err)
	}
}
