package sandbox_test

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	testsupport "github.com/Inforberi/financial-intelligence/sandbox/internal/testsupport"
)

// Explicit preparation only: ordinary go test never creates deployment keys.
func TestPrepareJWT(t *testing.T) {
	if os.Getenv("AUTH_SANDBOX_PREPARE") != "1" {
		t.Skip("run task sandbox:jwt against the existing local sandbox")
	}
	dir := filepath.Join(testsupport.SandboxDirectory(t), "jwt")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Never silently replace an existing signing key or a partially prepared bundle.
	files := []string{"private.pem", "jwks.json", "resources.json", "clients.json", "consumer-secret"}
	existing := 0
	for _, name := range files {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			existing++
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	if existing == len(files) {
		return
	}
	if existing != 0 {
		t.Fatal("partial JWT bundle; inspect tmp/sandbox/jwt, do not overwrite keys automatically")
	}
	private, public := testsupport.SyntheticSigningKey(t, "sandbox-1")
	testsupport.WritePrivate(t, filepath.Join(dir, "private.pem"), private)
	testsupport.WriteJSON(t, filepath.Join(dir, "jwks.json"), map[string]any{"keys": []any{public}})
	testsupport.WriteJSON(t, filepath.Join(dir, "resources.json"), map[string]any{"resources": []any{
		map[string]any{"audience": "sandbox-strict", "mode": "strict", "permissions": []string{"sandbox.records.read", "sandbox.records.write", "accounts.users.read"}},
		map[string]any{"audience": "sandbox-local", "mode": "local", "permissions": []string{"sandbox.records.read"}},
	}})
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	raw := base64.RawURLEncoding.EncodeToString(secret)
	hash := sha256.Sum256([]byte(raw))
	testsupport.WritePrivate(t, filepath.Join(dir, "consumer-secret"), []byte(raw))
	testsupport.WriteJSON(t, filepath.Join(dir, "clients.json"), map[string]any{"clients": []any{map[string]any{
		"id": "sandbox-consumer", "secretHashes": []string{hex.EncodeToString(hash[:])}, "audiences": []string{"sandbox-strict"},
	}}})
}
