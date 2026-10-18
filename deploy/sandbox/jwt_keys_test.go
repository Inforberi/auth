package sandbox_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func sandboxDirectory(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../../tmp/sandbox")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// Explicit preparation only: ordinary go test never creates deployment keys.
func TestPrepareJWT(t *testing.T) {
	if os.Getenv("AUTH_SANDBOX_PREPARE") != "1" {
		t.Skip("run task sandbox:jwt against the existing local sandbox")
	}
	dir := filepath.Join(sandboxDirectory(t), "jwt")
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
	private, public := syntheticSigningKey(t, "sandbox-1")
	writePrivate(t, filepath.Join(dir, "private.pem"), private)
	writeJSON(t, filepath.Join(dir, "jwks.json"), map[string]any{"keys": []any{public}})
	writeJSON(t, filepath.Join(dir, "resources.json"), map[string]any{"resources": []any{
		map[string]any{"audience": "sandbox-strict", "mode": "strict", "permissions": []string{"sandbox.records.read", "sandbox.records.write", "accounts.users.read"}},
		map[string]any{"audience": "sandbox-local", "mode": "local", "permissions": []string{"sandbox.records.read"}},
	}})
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	raw := base64.RawURLEncoding.EncodeToString(secret)
	hash := sha256.Sum256([]byte(raw))
	writePrivate(t, filepath.Join(dir, "consumer-secret"), []byte(raw))
	writeJSON(t, filepath.Join(dir, "clients.json"), map[string]any{"clients": []any{map[string]any{
		"id": "sandbox-consumer", "secretHashes": []string{hex.EncodeToString(hash[:])}, "audiences": []string{"sandbox-strict"},
	}}})
}

func syntheticSigningKey(t *testing.T, kid string) ([]byte, map[string]string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	coordinate := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	public := map[string]string{
		"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": kid,
		"x": coordinate(key.X.FillBytes(make([]byte, 32))), "y": coordinate(key.Y.FillBytes(make([]byte, 32))),
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), public
}

func writePrivate(t *testing.T, path string, data []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal("cannot persist synthetic sandbox fixture")
	}
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	writePrivate(t, path, data)
}
