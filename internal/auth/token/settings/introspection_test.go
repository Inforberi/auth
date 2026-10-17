package settings

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func TestIntrospectionManifest(t *testing.T) {
	valid := `{"clients":[{"id":"orders","secretHashes":["` + strings.Repeat("a", 64) + `"],"audiences":["orders"]}]}`
	for _, raw := range []string{`{}`, `{"clients":null}`, `{"clients":[]}`, strings.Replace(valid, `"clients"`, `"Clients"`, 1), strings.Replace(valid, `"id":"orders"`, `"id":"orders","id":"other"`, 1), strings.Replace(valid, `"audiences"`, `"Audiences"`, 1), strings.Replace(valid, `"id":"orders"`, `"id":null`, 1), strings.Replace(valid, `"id":"orders"`, `"id":"orders","extra":1`, 1), valid + `{}`} {
		if _, err := decodeIntrospectionClients([]byte(raw)); !errors.Is(err, authjwt.ErrConfiguration) {
			t.Fatal("invalid manifest accepted", raw, err)
		}
	}
	path := filepath.Join(t.TempDir(), "clients.json")
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	clients, err := LoadIntrospectionClients(path)
	if err != nil || len(clients) != 1 || clients[0].ID != "orders" {
		t.Fatal(clients, err)
	}
	if _, err := LoadIntrospectionClients(filepath.Dir(path)); err == nil {
		t.Fatal("directory accepted")
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 32769)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIntrospectionClients(path); err == nil {
		t.Fatal("unbounded manifest")
	}
}
