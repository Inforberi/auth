package access

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/access/settings"
)

func TestInvalidCatalogBeforeStorage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(path, []byte(`{"version":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(context.Background(), nil, settings.Config{CatalogFile: path}); err == nil {
		t.Fatal("invalid catalog reached storage")
	}
}
