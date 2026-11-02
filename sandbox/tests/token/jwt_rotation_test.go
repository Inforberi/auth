package sandbox_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
	testsupport "github.com/Inforberi/financial-intelligence/sandbox/internal/testsupport"
)

func TestJWTRotation(t *testing.T) {
	if os.Getenv("AUTH_SANDBOX_ROTATION") != "1" {
		t.Skip("explicit live key rotation; run task sandbox:jwt:rotation")
	}
	api, roots := testsupport.SandboxClient(t, false)
	testsupport.AssertKeyIDs(t, api, "sandbox-1")
	var baseline struct {
		Keys []json.RawMessage `json:"keys"`
	}
	testsupport.PrivateJSON(t, "jwt/jwks.json", &baseline)
	if len(baseline.Keys) != 1 {
		t.Fatal("expected the original single-key sandbox bundle")
	}
	browser := testsupport.UserLogin(t)
	dir, err := os.MkdirTemp(filepath.Join(testsupport.SandboxDirectory(t), "jwt"), "rotation-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		testsupport.RedeploySandboxAPI(t, api, "")
		testsupport.AssertKeyIDs(t, api, "sandbox-1")
		if err := os.RemoveAll(dir); err != nil {
			t.Error("could not remove generated rotation-only keys")
		}
	})
	kidA, kidB := filepath.Base(dir)+"-a", filepath.Base(dir)+"-b"
	privateA, publicA := testsupport.SyntheticSigningKey(t, kidA)
	privateB, publicB := testsupport.SyntheticSigningKey(t, kidB)
	pathA, pathB := filepath.Join(dir, "a.pem"), filepath.Join(dir, "b.pem")
	testsupport.WritePrivate(t, pathA, privateA)
	testsupport.WritePrivate(t, pathB, privateB)
	before := []any{baseline.Keys[0], publicA}
	overlap := []any{baseline.Keys[0], publicA, publicB}
	after := []any{baseline.Keys[0], publicB}

	t.Log("initial temporary signer A; original sandbox-1 remains trusted")
	testsupport.RedeploySandboxAPI(t, api, rotationPhase(t, dir, "initial", kidA, pathA, before))
	strict, local := testsupport.NewConsumer(t, roots, authjwt.Strict), testsupport.NewConsumer(t, roots, authjwt.Local)
	oldStrict, oldLocal := testsupport.Exchange(t, browser, "sandbox-strict"), testsupport.Exchange(t, browser, "sandbox-local")
	assertTokenKey(t, oldStrict, kidA)
	assertTokenKey(t, oldLocal, kidA)
	testsupport.Consume(t, strict, oldStrict.AccessToken, "sandbox.records.read", 204)
	testsupport.Consume(t, local, oldLocal.AccessToken, "sandbox.records.read", 204)

	t.Log("publish B before changing the signer; consumers refresh on their normal schedule")
	testsupport.RedeploySandboxAPI(t, api, rotationPhase(t, dir, "overlap", kidA, pathA, overlap))
	testsupport.AssertKeyIDs(t, api, "sandbox-1", kidA, kidB)
	rotationWait(t, 10100*time.Millisecond)
	if strict.Ready(t.Context()) != nil || local.Ready(t.Context()) != nil {
		t.Fatal("consumers did not accept overlap keys")
	}
	testsupport.RedeploySandboxAPI(t, api, rotationPhase(t, dir, "new-signer", kidB, pathB, overlap))
	newStrict, newLocal := testsupport.Exchange(t, browser, "sandbox-strict"), testsupport.Exchange(t, browser, "sandbox-local")
	assertTokenKey(t, newStrict, kidB)
	assertTokenKey(t, newLocal, kidB)
	testsupport.Consume(t, strict, oldStrict.AccessToken, "sandbox.records.read", 204)
	testsupport.Consume(t, strict, newStrict.AccessToken, "sandbox.records.read", 204)
	testsupport.Consume(t, local, oldLocal.AccessToken, "sandbox.records.read", 204)
	testsupport.Consume(t, local, newLocal.AccessToken, "sandbox.records.read", 204)

	// Deliberate early distrust, not planned retirement before the documented TTL+skew drain.
	t.Log("remove A from authoritative trust while its tokens are still unexpired")
	testsupport.RedeploySandboxAPI(t, api, rotationPhase(t, dir, "retired", kidB, pathB, after))
	testsupport.AssertKeyIDs(t, api, "sandbox-1", kidB)
	rotationWait(t, 10100*time.Millisecond)
	if strict.Ready(t.Context()) != nil || local.Ready(t.Context()) != nil {
		t.Fatal("consumers did not refresh retired trust")
	}
	testsupport.AssertUnexpired(t, oldStrict, oldLocal)
	testsupport.Consume(t, strict, oldStrict.AccessToken, "sandbox.records.read", 401)
	testsupport.Consume(t, local, oldLocal.AccessToken, "sandbox.records.read", 401)
	testsupport.Consume(t, strict, newStrict.AccessToken, "sandbox.records.read", 204)
	testsupport.Consume(t, local, newLocal.AccessToken, "sandbox.records.read", 204)

	// Fresh owners give a known upper bound on trust timestamps without a test clock override.
	strict, local = testsupport.NewConsumer(t, roots, authjwt.Strict), testsupport.NewConsumer(t, roots, authjwt.Local)
	trustedFrom := time.Now()
	t.Log("stop the actual Auth API: strict loses authority, local retains only fresh trust")
	testsupport.DockerDependency(t, "stop", "api")
	testsupport.Consume(t, strict, newStrict.AccessToken, "sandbox.records.read", 503)
	testsupport.Consume(t, local, newLocal.AccessToken, "sandbox.records.read", 204)
	rotationWait(t, 10100*time.Millisecond)
	testsupport.Consume(t, local, newLocal.AccessToken, "sandbox.records.read", 204)
	rotationWait(t, time.Until(trustedFrom.Add(authjwt.MaxKeyAge+time.Second)))
	testsupport.AssertUnexpired(t, newStrict, newLocal)
	if !errors.Is(strict.Ready(t.Context()), authjwt.ErrKeysUnavailable) || !errors.Is(local.Ready(t.Context()), authjwt.ErrKeysUnavailable) {
		t.Fatal("failed JWKS fetch extended the original trust lifetime")
	}
	testsupport.Consume(t, strict, newStrict.AccessToken, "sandbox.records.read", 503)
	testsupport.Consume(t, local, newLocal.AccessToken, "sandbox.records.read", 503)

	t.Log("restart Auth; restore trust after normal fetch backoff, without a new login")
	testsupport.DockerDependency(t, "start", "api")
	testsupport.WaitReadiness(t, api, 200)
	rotationWait(t, 10100*time.Millisecond)
	testsupport.Consume(t, strict, newStrict.AccessToken, "sandbox.records.read", 204)
	testsupport.Consume(t, local, newLocal.AccessToken, "sandbox.records.read", 204)
	testsupport.Consume(t, strict, oldStrict.AccessToken, "sandbox.records.read", 401)
	testsupport.Consume(t, local, oldLocal.AccessToken, "sandbox.records.read", 401)
}

func rotationWait(t *testing.T, delay time.Duration) {
	t.Helper()
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-t.Context().Done():
		t.Fatal("rotation wait cancelled")
	}
}

func assertTokenKey(t *testing.T, token testsupport.TokenResponse, expected string) {
	t.Helper()
	header, _, ok := strings.Cut(token.AccessToken, ".")
	raw, err := base64.RawURLEncoding.DecodeString(header)
	var parsed struct {
		ID string `json:"kid"`
	}
	if !ok || err != nil || json.Unmarshal(raw, &parsed) != nil || parsed.ID != expected {
		t.Fatal("issuance did not use the selected signing key")
	}
}
