package testsupport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"
)

func SyntheticSigningKey(t *testing.T, kid string) ([]byte, map[string]string) {
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

func WritePrivate(t *testing.T, path string, data []byte) {
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

func WriteJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	WritePrivate(t, path, data)
}
