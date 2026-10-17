package postgres

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5/pgxpool"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	tokendomain "github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	tokenpostgres "github.com/Inforberi/financial-intelligence/internal/auth/token/repository/postgres"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/signing"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type tokenBudget func(context.Context, tokenservice.ExchangeInput) error

func (b tokenBudget) Allow(ctx context.Context, input tokenservice.ExchangeInput) error {
	return b(ctx, input)
}

func (b tokenBudget) AllowCredentialLookup(ctx context.Context, ip string) error {
	return b(ctx, tokenservice.ExchangeInput{IP: ip})
}

func (b tokenBudget) AllowNative(ctx context.Context, user accountdomain.UserID, ip string) error {
	input := tokenservice.ExchangeInput{IP: ip}
	input.Actor.UserID = user
	return b(ctx, input)
}

func jwtSigningFixture(t *testing.T) (*signing.Signer, *authjwt.PublicKeys) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	public, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "test", Algorithm: "ES256", Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := authjwt.ParsePublicKeys(public)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := signing.New("https://auth.example", "test", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), keys)
	if err != nil {
		t.Fatal(err)
	}
	return signer, keys
}

func jwtActor(t *testing.T, db *pgxpool.Pool, ctx context.Context) tokenservice.ExchangeInput {
	t.Helper()
	actor := accessPrincipal(t, db, ctx)
	var role string
	if err := db.QueryRow(ctx, `INSERT INTO auth.roles(key,name,mfa_required) VALUES ($1,'JWT fixture',true) RETURNING id`,
		"jwt_"+strings.ReplaceAll(string(actor.UserID), "-", "")).Scan(&role); err != nil {
		t.Fatal(err)
	}
	accessExec(t, db, ctx, `INSERT INTO auth.role_permissions(role_id,permission_key) VALUES ($1,'orders.read'),($1,'orders.write')`, role)
	accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) VALUES ($1,$2)`, actor.UserID, role)
	actor = renewAccessPrincipal(t, db, ctx, actor.UserID)
	input := tokenservice.ExchangeInput{Actor: actor, Audience: "orders", Scope: []accessdomain.PermissionKey{"orders.read"}, IP: "192.0.2.1"}
	if err := db.QueryRow(ctx, `SELECT id FROM auth.sessions WHERE token_hash=$1`, actor.TokenHash).Scan(&input.SessionID); err != nil {
		t.Fatal(err)
	}
	return input
}

func checkJWTExchange(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Helper()
	signer, keys := jwtSigningFixture(t)
	catalog, err := settings.NewCatalog([]settings.Permission{{Key: "orders.read", Name: "Read"}, {Key: "orders.write", Name: "Write"}})
	if err != nil {
		t.Fatal(err)
	}
	repo := tokenpostgres.New(db)
	svc, err := tokenservice.New(repo, signer, tokenBudget(func(context.Context, tokenservice.ExchangeInput) error { return nil }), tokengenerate.New(),
		tokenservice.Config{AccessTTL: 2 * time.Minute, Resources: []tokenservice.Resource{{Audience: "orders", Permissions: []accessdomain.PermissionKey{"orders.read", "orders.write"}}}}, catalog)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("claims deadlines no refresh and retained audit", func(t *testing.T) {
		input := jwtActor(t, db, ctx)
		accessExec(t, db, ctx, `UPDATE auth.sessions SET expires_at=clock_timestamp()+interval '40 seconds' WHERE token_hash=$1`, input.Actor.TokenHash)
		var expiry, absolute, primary, mfa time.Time
		if err := db.QueryRow(ctx, `SELECT expires_at,absolute_expires_at,primary_verified_at,mfa_verified_at FROM auth.sessions WHERE token_hash=$1`, input.Actor.TokenHash).
			Scan(&expiry, &absolute, &primary, &mfa); err != nil {
			t.Fatal(err)
		}
		result, err := svc.Exchange(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		verifier, err := authjwt.NewVerifier(authjwt.Expectations{Issuer: "https://auth.example", Audience: "orders", Mode: authjwt.Strict}, keys, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		claims, err := verifier.VerifySignature(ctx, result.Raw, time.Now())
		if err != nil || claims.Subject != string(input.Actor.UserID) || claims.SessionID != input.SessionID || claims.ExpiresAt != expiry.Unix() || claims.AuthTime != primary.Unix() ||
			claims.MFATime == nil || *claims.MFATime != mfa.Unix() || claims.Scope != "orders.read" || claims.ID != result.ID {
			t.Fatal("claims differ from ledger", err)
		}
		var unchanged, audited bool
		if err := db.QueryRow(ctx, `SELECT expires_at=$2 AND absolute_expires_at=$3 AND primary_verified_at=$4 AND mfa_verified_at=$5 FROM auth.sessions WHERE token_hash=$1`,
			input.Actor.TokenHash, expiry, absolute, primary, mfa).Scan(&unchanged); err != nil || !unchanged {
			t.Fatal("issuance refreshed session/proofs", err)
		}
		if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.token_issuance_audit WHERE token_id=$1 AND user_id=$2 AND session_id=$3 AND scope=ARRAY['orders.read'] AND validation_mode='strict')`,
			result.ID, input.Actor.UserID, input.SessionID).Scan(&audited); err != nil || !audited {
			t.Fatal("missing atomic audit", err)
		}
		accessExec(t, db, ctx, `UPDATE auth.token_issuance_audit SET created_at=created_at-interval '181 days',expires_at=expires_at-interval '181 days' WHERE token_id=$1`, result.ID)
		if _, err := accountpostgres.New(db).PurgeRetention(ctx, retentionPolicy()); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.token_issuance_audit WHERE token_id=$1)`, result.ID).Scan(&audited); err != nil || audited {
			t.Fatal("issuance audit not purged", err)
		}
	})

	for _, test := range []struct {
		name, query string
		want        error
	}{
		{"blocked", `UPDATE auth.users SET status='blocked' WHERE id=$1`, sessiondomain.ErrSessionNotFound},
		{"deleted", `UPDATE auth.users SET status='blocked',deleted_at=clock_timestamp() WHERE id=$1`, sessiondomain.ErrSessionNotFound},
		{"version", `UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`, sessiondomain.ErrSessionNotFound},
		{"logout", `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE user_id=$1`, sessiondomain.ErrSessionNotFound},
		{"expired", `UPDATE auth.sessions SET expires_at=created_at+interval '1 microsecond' WHERE user_id=$1`, sessiondomain.ErrSessionNotFound},
		{"permission removed", `DELETE FROM auth.role_permissions WHERE role_id IN (SELECT role_id FROM auth.user_roles WHERE user_id=$1) AND permission_key='orders.read'`, tokendomain.ErrForbidden},
		{"role revision", `UPDATE auth.roles SET session_revision=session_revision+1 WHERE id IN (SELECT role_id FROM auth.user_roles WHERE user_id=$1)`, sessiondomain.ErrSessionNotFound},
		{"MFA missing", `UPDATE auth.sessions SET mfa_verified_at=NULL WHERE user_id=$1`, sessiondomain.ErrMFARequired},
		{"primary proof missing", `UPDATE auth.sessions SET primary_method=NULL,primary_verified_at=NULL,mfa_verified_at=NULL WHERE user_id=$1`, sessiondomain.ErrSessionNotFound},
		{"factor removed", `DELETE FROM auth.mfa_totp WHERE user_id=$1`, sessiondomain.ErrMFARequired},
		{"activation pending", `INSERT INTO auth.account_provisions(actor_id,request_key,fingerprint,user_id) VALUES ($1,gen_random_uuid(),repeat('a',64),$1)`, sessiondomain.ErrSessionNotFound},
		{"password change pending", `INSERT INTO auth.account_provisions(actor_id,request_key,fingerprint,user_id,activated_at,password_change_required) VALUES ($1,gen_random_uuid(),repeat('a',64),$1,clock_timestamp(),true)`, sessiondomain.ErrSessionNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := jwtActor(t, db, ctx)
			accessExec(t, db, ctx, test.query, input.Actor.UserID)
			result, err := svc.Exchange(ctx, input)
			if result != nil || !errors.Is(err, test.want) {
				t.Fatal("invalid issuance accepted", test.name, err)
			}
			var count int
			if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.token_issuance_audit WHERE session_id=$1`, input.SessionID).Scan(&count); err != nil || count != 0 {
				t.Fatal("failed issuance audited", count, err)
			}
		})
	}

	t.Run("wrong session and hash", func(t *testing.T) {
		input := jwtActor(t, db, ctx)
		other := jwtActor(t, db, ctx)
		original := input
		input.SessionID = other.SessionID
		if result, err := svc.Exchange(ctx, input); result != nil || !errors.Is(err, sessiondomain.ErrSessionNotFound) {
			t.Fatal("sid impersonation", err)
		}
		input = original
		input.Actor.TokenHash = strings.Repeat("f", 64)
		if result, err := svc.Exchange(ctx, input); result != nil || !errors.Is(err, sessiondomain.ErrSessionNotFound) {
			t.Fatal("hash impersonation", err)
		}
	})

	t.Run("signing failure rollback", func(t *testing.T) {
		input := jwtActor(t, db, ctx)
		result, err := repo.Exchange(ctx, input, authjwt.Strict, func(context.Context, tokenservice.SessionProof) (*signing.SignedToken, error) {
			return nil, authjwt.ErrBusy
		})
		if result != nil || !errors.Is(err, authjwt.ErrBusy) {
			t.Fatal(err)
		}
		if _, err := svc.Exchange(ctx, input); err != nil {
			t.Fatal("transaction lock leaked", err)
		}
	})

	t.Run("current verification without primary login revocation", func(t *testing.T) {
		input := jwtActor(t, db, ctx)
		var previous string
		var enabled bool
		if err := db.QueryRow(ctx, `SELECT password_email_verification,password_enabled FROM auth.auth_settings WHERE singleton`).Scan(&previous, &enabled); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			accessExec(t, db, ctx, `UPDATE auth.auth_settings SET password_email_verification=$1,password_enabled=$2 WHERE singleton`, previous, enabled)
		})
		var emailID string
		if err := db.QueryRow(ctx, `INSERT INTO auth.user_emails(user_id,email) VALUES ($1,$2) RETURNING id`, input.Actor.UserID, string(input.Actor.UserID)+"@example.test").Scan(&emailID); err != nil {
			t.Fatal(err)
		}
		accessExec(t, db, ctx, `INSERT INTO auth.password_credentials(user_id,email_id,password_hash) VALUES ($1,$2,'synthetic hash')`, input.Actor.UserID, emailID)
		accessExec(t, db, ctx, `UPDATE auth.auth_settings SET password_email_verification='required',password_enabled=false WHERE singleton`)
		if result, err := svc.Exchange(ctx, input); result != nil || !errors.Is(err, accountdomain.ErrEmailUnverified) {
			t.Fatal("existing unverified password session bypassed policy", err)
		}
		accessExec(t, db, ctx, `UPDATE auth.user_emails SET verified_at=clock_timestamp() WHERE id=$1`, emailID)
		if _, err := svc.Exchange(ctx, input); err != nil {
			t.Fatal("disabled primary method unexpectedly revoked completed session", err)
		}
	})

	t.Run("commit failure hides token and audit", func(t *testing.T) {
		input := jwtActor(t, db, ctx)
		accessExec(t, db, ctx, `CREATE FUNCTION auth.reject_test_issuance() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic commit failure'; END $$;
			CREATE CONSTRAINT TRIGGER reject_test_issuance AFTER INSERT ON auth.token_issuance_audit DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION auth.reject_test_issuance()`)
		t.Cleanup(func() {
			accessExec(t, db, ctx, `DROP TRIGGER reject_test_issuance ON auth.token_issuance_audit; DROP FUNCTION auth.reject_test_issuance()`)
		})
		result, err := svc.Exchange(ctx, input)
		if result != nil || err == nil {
			t.Fatal("token returned before commit")
		}
		var count int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.token_issuance_audit WHERE session_id=$1`, input.SessionID).Scan(&count); err != nil || count != 0 {
			t.Fatal("commit rollback failed", err)
		}
	})
	checkJWTExchangeLocks(t, db, ctx)
}
