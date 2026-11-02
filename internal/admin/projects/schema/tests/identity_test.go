package schema_test

import (
	"encoding/hex"
	"testing"

	projectschema "github.com/Inforberi/financial-intelligence/internal/admin/projects/schema"
)

func TestProjectSchemaChecksum(t *testing.T) {
	first := projectschema.ProjectSchemaChecksum("runtime grants A")
	decoded, err := hex.DecodeString(first)
	if err != nil || len(decoded) != 32 || first != projectschema.ProjectSchemaChecksum("runtime grants A") ||
		first == projectschema.ProjectSchemaChecksum("runtime grants B") {
		t.Fatal("invalid or unbound schema checksum")
	}
}
