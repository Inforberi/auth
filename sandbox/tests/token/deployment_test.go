package sandbox_test

import (
	"path/filepath"
	"testing"

	testsupport "github.com/Inforberi/financial-intelligence/sandbox/internal/testsupport"
)

func rotationPhase(t *testing.T, dir, name, kid, private string, keys []any) string {
	t.Helper()
	jwks := filepath.Join(dir, name+"-jwks.json")
	testsupport.WriteJSON(t, jwks, map[string]any{"keys": keys})
	mount := func(source, target string) map[string]any {
		return map[string]any{
			"type": "bind", "source": source, "target": target,
			"read_only": true, "bind": map[string]bool{"create_host_path": false},
		}
	}
	path := filepath.Join(dir, name+"-compose.json")
	testsupport.WriteJSON(t, path, map[string]any{"services": map[string]any{"api": map[string]any{
		"environment": map[string]string{"JWT_SIGNING_KEY_ID": kid, "JWT_ACCESS_TTL": "3m"},
		"volumes":     []any{mount(private, "/sandbox/jwt/private.pem"), mount(jwks, "/sandbox/jwt/jwks.json")},
	}}})
	return path
}
